"""Shared seams: terminal IO, command runner, errors."""
from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

# (argv) -> (returncode, stdout). Real one shells out; tests pass a fake.
Runner = Callable[[list[str]], tuple[int, str]]


class OnboardError(Exception):
    """A refusal (tier/tailnet/grant rule, bad input) or an aborted confirmation."""


def subprocess_runner(argv: list[str]) -> tuple[int, str]:
    # stdin/stderr stay attached: step prompts for the provisioner/p12 passwords itself.
    p = subprocess.run(argv, stdout=subprocess.PIPE, text=True, check=False)
    return p.returncode, p.stdout


@dataclass
class IO:
    """Output sink + prompt source. Tests use IO(answers=[...]) and read `.lines`."""
    answers: list[str] | None = None
    lines: list[str] = field(default_factory=list)
    echo: bool = False

    def out(self, text: str = "") -> None:
        self.lines.append(text)
        if self.echo:
            print(text)

    def ask(self, prompt: str) -> str:
        if self.answers is None:
            return input(prompt)
        if not self.answers:
            raise OnboardError(f"no answer for prompt: {prompt}")
        ans = self.answers.pop(0)
        self.out(f"{prompt}{ans}")
        return ans

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def terminal_io() -> IO:
    return IO(echo=True, answers=None if sys.stdin.isatty() else [])
