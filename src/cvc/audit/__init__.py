"""Audit admin process (D24): read-only checks -> cvc.audit.v1 findings -> MQTT.

Not an LLM and holds no write access to the registry or vault. Add a check with
`@cvc.audit.checks.check("name")` on `fn(ctx) -> list[Finding]`.
"""
from cvc.audit.checks import CHECKS, Context, check, run_checks
from cvc.audit.findings import SCHEMA, Finding, finding_id, merge, summary

__all__ = ["CHECKS", "SCHEMA", "Context", "Finding", "check", "finding_id", "merge",
           "run_checks", "summary"]
