"""everything surrounding Studycard
"""

import typing

from dataclasses import dataclass, field
from solders.keypair import Keypair
from solders.pubkey import Pubkey


@dataclass
class Studycard:
    """primary data entity in the system"""

    # address of the struct, on chain, if any
    address: Pubkey

    # who had contributed the Studycard
    contributor: Pubkey

    # actual IP owner
    owner: Pubkey

    # current holder
    holder: Pubkey

    # a label for the card
    name: str

    # card access type
    access: typing.Literal["rent", "free"] = "free"

    # for how long it can be rented (seconds)
    rent_period: int = 60 * 15  # 15m as a default

    # for how long can the rent get extended when NFT is not actively used
    inactive_period: int = 60 * 60 * 24  # 24h as a default

    # last rent timestamp
    rented_at: int = 0

    # filename->checksum pair
    media: dict[str, str] = field(default_factory=dict)

    # media used as card front
    front: list[str] = field(default_factory=lambda: [])

    # media used as card back
    back: list[str] = field(default_factory=lambda: [])

    @classmethod
    def create(cls, *args: typing.Any) -> "Studycard":
        """factory

        since: 0.0.1
        """
        return cls(*args)

    @property
    def free_at(self) -> int:
        return self.rented_at + self.inactive_period + self.rent_period

    @property
    def decks(self) -> list[str]:
        """find and return IDs of decks this card is used in"""
        return []
