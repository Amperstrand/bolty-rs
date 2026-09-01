"""Card registry: the UID safety contract for all mutation tests."""

from dataclasses import dataclass, field
from pathlib import Path
import tomllib

DEFAULT_REGISTRY = Path(__file__).parent / "cards.toml"


class CardError(RuntimeError):
    """Raised when a card/op combination is not permitted by the registry."""


@dataclass(frozen=True)
class Card:
    uid: str
    alias: str
    reader_hint: str
    ops: tuple[str, ...]
    state: str

    def permits(self, op: str) -> bool:
        return op in self.ops


class CardRegistry:
    def __init__(self, path: Path = DEFAULT_REGISTRY):
        with open(path, "rb") as f:
            data = tomllib.load(f)
        self._cards: dict[str, Card] = {}
        for uid, spec in data.get("cards", {}).items():
            self._cards[uid.lower()] = Card(
                uid=uid.lower(),
                alias=spec.get("alias", uid),
                reader_hint=spec.get("reader_hint", "any"),
                ops=tuple(spec.get("ops", ["read"])),
                state=spec.get("state", "any"),
            )

    def lookup(self, uid: str) -> Card | None:
        return self._cards.get(uid.lower())

    def require(self, uid: str, op: str) -> Card:
        """Return the card iff `op` is permitted; raise CardError otherwise."""
        card = self.lookup(uid)
        if card is None:
            raise CardError(
                f"card {uid} is not in the HIL registry ({DEFAULT_REGISTRY}) — refusing {op}"
            )
        if not card.permits(op):
            raise CardError(
                f"card {uid} ({card.alias}) does not permit '{op}' "
                f"(allowed: {', '.join(card.ops)})"
            )
        return card

    def uids_allowing(self, op: str) -> list[str]:
        return [c.uid for c in self._cards.values() if c.permits(op)]
