"""Public surface of the ``recovery_input`` screen package.

Exports ``RecoveryInputScreen``, the top-level widget that hosts the
two-step vault-password recovery flow.  All implementation details live in
``screen``, ``step1``, and ``step2``.
"""
from .screen import RecoveryInputScreen

__all__ = ["RecoveryInputScreen"]
