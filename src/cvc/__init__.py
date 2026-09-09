"""cvc — credential vault consolidation.

Import passwords into Vaultwarden, remind on rotation, back up / recover, and broker
least-privilege agent access with an audit trail. See docs/ARCHITECTURE.md.

SCAFFOLD: no component that touches real secrets is implemented; each raises
NotImplementedError referencing the Phase-0 decision (docs/DECISIONS.md) that unblocks it.
"""

__version__ = "0.0.0"
