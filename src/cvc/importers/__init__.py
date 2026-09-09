"""Phase 1 importers: source password stores → normalized items → vault.

Safety: importers operate on explicit input files, never auto-discover, and callers must shred
plaintext exports after import (see cvc.importers.__main__).
"""
