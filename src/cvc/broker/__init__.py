"""Phase 4: least-privilege credential broker for Playwright agents.

Trust model: agents are semi-trusted; a compromised agent is an assumed condition. Access is
default-deny, per-credential, purpose-bound, and audited BEFORE any secret is returned. This
package must pass an Opus security review before it ships (see docs/THREAT-MODEL.md).
"""
