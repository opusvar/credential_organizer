"""Onboarding wizard: `cvc onboard person|agent` (also `cvc-onboard`).

Every step prints what it will do and how to verify it. `--dry-run` shows everything and
writes nothing. Nothing external (step-ca, Tailscale, Authentik) is contacted unless
`--execute` is given, and then only through injectable seams (Runner, AuthentikClient) so
tests use fakes. Registry writes reuse cvc.access edit helpers and validators.
"""
from cvc.onboard.authentik import AuthentikClient, HttpAuthentik, RecordingAuthentik
from cvc.onboard.certs import CertCommand, cert_commands, expected_sans, provisioner_for
from cvc.onboard.core import IO, OnboardError, Runner
from cvc.onboard.wizard import (
    AgentSpec,
    DeviceSpec,
    HwKeySpec,
    PersonSpec,
    onboard_agent,
    onboard_person,
)

__all__ = [
    "IO",
    "AgentSpec",
    "AuthentikClient",
    "CertCommand",
    "DeviceSpec",
    "HttpAuthentik",
    "HwKeySpec",
    "OnboardError",
    "PersonSpec",
    "RecordingAuthentik",
    "Runner",
    "cert_commands",
    "expected_sans",
    "onboard_agent",
    "onboard_person",
    "provisioner_for",
]
