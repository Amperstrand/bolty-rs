"""HIL test framework core: preflight, card safety, role management.

Design contract:
- Every mutation test goes through the cards.toml registry (UID + op guard).
- Preflight checks are composable and report ok/warn/fail with details.
- Role switches use a context manager that ALWAYS restores (exception-safe).
- The framework runs under plain pytest (make test-hil) with zero LLM involvement.
"""

from .cards import CardRegistry, CardError
from .preflight import Preflight, Check
from .bolty import BoltyCli, BoltyError
from .roles import role_guard

__all__ = [
    "CardRegistry", "CardError",
    "Preflight", "Check",
    "BoltyCli", "BoltyError",
    "role_guard",
]
