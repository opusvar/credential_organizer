"""Printable estate recovery kit ("legacy recovery code") sheet (D15 addendum 2).

Fully offline: the QR is made locally with ``segno`` (pure python, optional extra
``cvc[estate]``) and the PDF is written by a minimal pure-python writer below (vector QR modules
+ Helvetica text). No network calls, no third-party services. The sheet is written 0600 to a
path the caller chooses, never to the state dir, and its contents are never logged.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from cvc.takeover.estate import ALPHABET, SYMBOLS, format_code, normalize
from cvc.takeover.model import TakeoverError

URI_PREFIX = "cvc-estate:v1:"
_URI = re.compile(r"^cvc-estate:v(\d+):([0-9A-Za-z-]+)$")
INSTALL_HINT = ("the estate kit sheet needs the optional QR library: "
                "pip install 'cvc[estate]'  (or: pip install segno)")


def build_uri(code: str) -> str:
    raw = normalize(code)
    if len(raw) != SYMBOLS or any(c not in ALPHABET for c in raw):
        raise TakeoverError("not an estate recovery code")
    return URI_PREFIX + raw


def parse_code(text: str) -> str:
    """Accept a typed code (any case/spacing/dashes) or a scanned ``cvc-estate:v1:`` URI;
    return the normalized code."""
    t = text.strip()
    m = _URI.match(t)
    if m:
        if m.group(1) != "1":
            raise TakeoverError(f"unsupported estate kit version v{m.group(1)}")
        t = m.group(2)
    elif t.lower().startswith("cvc-estate:"):
        raise TakeoverError("malformed estate kit URI")
    return normalize(t)


def _segno():
    try:
        import segno
    except ImportError:
        raise TakeoverError(INSTALL_HINT) from None
    return segno


def qr_matrix(payload: str) -> list[list[int]]:
    q = _segno().make(payload, error="m", micro=False)
    return [list(row) for row in q.matrix]


def terminal_qr(payload: str) -> str:
    """QR as text (two modules per character row, quiet zone included)."""
    m = qr_matrix(payload)
    n, b = len(m), 4
    full = [[0] * (n + 2 * b) for _ in range(b)] + \
        [[0] * b + r + [0] * b for r in m] + [[0] * (n + 2 * b) for _ in range(b + 1)]
    chars = {(0, 0): "█", (1, 1): " ", (1, 0): "▄", (0, 1): "▀"}  # light bg
    return "\n".join("".join(chars[(full[y][x], full[y + 1][x])] for x in range(len(full[0])))
                     for y in range(0, len(full) - 1, 2))


def instructions(code: str, kit_id: str, generated: str) -> list[str]:
    groups = format_code(normalize(code)).replace("-", "  ")
    return [
        "LEGACY RECOVERY CODE  -  cvc estate recovery kit",
        f"Generated {generated}    Kit id {kit_id} (identifies the kit; it is not the code)",
        "",
        f"Code:  {groups}",
        "",
        "WHAT THIS IS",
        "This code starts a 180-day takeover of one owner's accounts (password vault and",
        "home-lab access) when that owner has died or cannot act. Using it alerts ALL owners",
        "immediately, on every channel.",
        "",
        "WHO SHOULD USE IT",
        "A surviving owner, or an executor working together with a surviving owner.",
        "",
        "WHAT YOU NEED",
        "An owner's registered device certificate, that owner's YubiKey, and their passkey or",
        "Vaultwarden master password. The code alone is not enough.",
        "",
        "HOW TO USE IT",
        "1. On the owner's device, install cvc and run:  cvc takeover start --estate-kit",
        "2. Follow the prompts: device certificate, YubiKey, passkey/password, target owner.",
        "3. When asked for the estate recovery kit code, scan the QR code or type the code.",
        "4. Read the summary and type the target's name to confirm.",
        "",
        "WHAT HAPPENS NEXT",
        "Day 15: read-only view of the target's vault. Day 180: the takeover can be completed.",
        "Every owner is alerted at the start and repeatedly until completion.",
        "",
        "HOW IT CAN BE STOPPED",
        "Until day 180 the target, or any other owner, can cancel with their own YubiKey:",
        "cvc takeover cancel <id>.",
        "",
        "THIS CODE WORKS ONCE. After use it is void; a new kit must be generated and printed",
        "(cvc takeover estate-kit generate) and this sheet destroyed.",
        "",
        "KEEP IN A SAFETY DEPOSIT BOX. DO NOT PHOTOGRAPH OR STORE DIGITALLY.",
    ]


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf(code: str, kit_id: str, generated: str) -> bytes:
    """One A4 page: QR (vector rectangles) top right, instructions as Helvetica text."""
    m = qr_matrix(build_uri(code))
    W, H = 595, 842
    mod = 3.6
    size = len(m) * mod
    x0, y0 = W - 40 - size, H - 40 - size
    ops = ["0 0 0 rg"]
    for r, row in enumerate(m):
        for c, v in enumerate(row):
            if v:
                ops.append(f"{x0 + c * mod:.2f} {y0 + (len(m) - 1 - r) * mod:.2f} "
                           f"{mod:.2f} {mod:.2f} re")
    ops.append("f")
    ops.append("BT /F1 9 Tf 12 TL 40 800 Td")
    for i, line in enumerate(instructions(code, kit_id, generated)):
        font = "/F2 11 Tf" if i in (0, 3) or line.isupper() else "/F1 9 Tf"
        ops.append(f"{font} ({_esc(line)}) Tj T*")
    ops.append("ET")
    content = "\n".join(ops).encode("latin-1")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Contents 4 0 R "
         "/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>").encode(),
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content
        + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
            ).encode()
    return bytes(out)


def write_sheet(path: str | os.PathLike, code: str, kit_id: str, generated: str,
                state_dir: str | os.PathLike | None = None) -> Path:
    p = Path(path).expanduser()
    if p.is_dir() or str(path).endswith(os.sep):
        p = p / f"estate-kit-{kit_id}.pdf"
    if state_dir is not None:
        sd = Path(state_dir).expanduser().resolve()
        if sd == p.resolve().parent or sd in p.resolve().parents:
            raise TakeoverError("refused: never write the estate kit sheet into the state dir")
    data = render_pdf(code, kit_id, generated)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(p, 0o600)
    return p


def generate_and_emit(kit, owner: str, when: str, out_path: str | os.PathLike = ".",
                      terminal: bool = False, out=print) -> tuple[str, Path | None]:
    """Generate (or rotate) the kit and hand the code over exactly once: as a 0600 PDF sheet at
    ``out_path`` (default: current dir) or, with ``terminal``, as a text QR on screen. The QR
    library is checked first, so a missing extra never creates a kit nobody can print."""
    _segno()
    code = kit.generate(owner, when)
    st = kit.status()
    kit_id, generated = st["kit_id"], str(st["generated_at"])[:10]
    if terminal:
        out(terminal_qr(build_uri(code)))
        out("\n".join(instructions(code, kit_id, generated)))
        out("Copy this to paper now, then clear the screen and scrollback.")
        return kit_id, None
    path = write_sheet(out_path, code, kit_id, generated, state_dir=kit.path.parent)
    out(f"wrote estate kit sheet {path} (mode 0600, kit id {kit_id})")
    out(f"Print it now, then securely delete the file: shred -u {path}  (macOS: rm -P {path})")
    return kit_id, path
