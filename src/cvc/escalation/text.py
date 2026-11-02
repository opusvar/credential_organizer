"""Shared free-text normalizer for escalation fields (purpose, justification).

Follows the project text-input rules: valid code points only, NFC, no special whitespace or
invisible characters (checked before trimming), trim, collapse spaces, re-NFC, non-empty.
The `regex` package is not a dependency, so emoji are kept as-is (they are ordinary
assigned code points) and only combining-mark runs are capped (anti-zalgo).
"""
from __future__ import annotations

import unicodedata

MAX_COMBINING = 3


class TextError(ValueError):
    def __init__(self, code: str, field: str):
        super().__init__(f"{field}: {code}")
        self.code, self.field = code, field


# Explicit lists, never str.isspace().
_BAD_WS = frozenset(
    [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
    + list(range(0x2000, 0x200B)))
_INVISIBLE = frozenset([0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]
                       + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
                       + [0x200E, 0x200F, 0x061C])
_EMOJI_JOINERS = frozenset([0x200D, 0xFE0F, 0xFE0E])


def _noncharacter(cp: int) -> bool:
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def normalize(value: object, field: str, max_len: int = 512) -> str:
    if not isinstance(value, str):
        raise TextError("invalid_type", field)
    for ch in value:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF or _noncharacter(cp):
            raise TextError("invalid_encoding", field)
    s = unicodedata.normalize("NFC", value)
    prev = ""
    for i, ch in enumerate(s):
        cp = ord(ch)
        if cp in _BAD_WS:
            raise TextError("invalid_whitespace", field)
        if cp in _INVISIBLE:
            # ZWJ is allowed only between two emoji-ish (symbol) characters.
            nxt = s[i + 1] if i + 1 < len(s) else ""
            if cp == 0x200D and prev and nxt and unicodedata.category(prev) == "So" \
                    and unicodedata.category(nxt) == "So":
                prev = ch
                continue
            raise TextError("invalid_whitespace", field)
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Co", "Cn", "Cs") and cp not in _EMOJI_JOINERS:
            raise TextError("invalid_characters", field)
        prev = ch
    out, run = [], 0
    for ch in s:
        if unicodedata.combining(ch):
            run += 1
            if run > MAX_COMBINING or not out:
                continue
        else:
            run = 0
        out.append(ch)
    s = " ".join("".join(out).strip(" ").split(" "))
    while "  " in s:
        s = s.replace("  ", " ")
    s = unicodedata.normalize("NFC", s)
    if not s:
        raise TextError("empty", field)
    if len(s) > max_len:
        raise TextError("too_long", field)
    return s
