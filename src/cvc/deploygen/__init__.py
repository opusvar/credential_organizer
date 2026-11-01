"""Offline generators for cluster manifests (Traefik routes, tier-gate config).

Nothing here talks to a cluster or the network: output is YAML on stdout/a file, for review
and a manual `kubectl apply`. See docs/DEPLOY.md.
"""
