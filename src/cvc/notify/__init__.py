"""Push notifications for approvals and audits via ntfy (self-hosted and/or ntfy.sh).

Modules: config (env/site/registry), message (redaction rule), ntfy (HTTP + failover),
notifier (routing, quiet hours, escalation, digest), hooks (no-op unless configured).
Kept import-light so cvc.approvals / cvc.audit can import the hook without cycles.
See docs/NOTIFICATIONS.md. Notification failure never changes an approval outcome.
"""
