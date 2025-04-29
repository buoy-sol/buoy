"""everything surrounding Studyunit
"""

import typing

from dataclasses import dataclass
from solders.pubkey import Pubkey


@dataclass
class Studyunit:
    """primary data entity in the system"""

    # unit access type
    access: typing.Literal["rent", "free"] = "free"

    # address of the struct, on chain, if any
    address: Pubkey

    # who had contributed the Studyunit
    contributor: Pubkey

    # actual IP owner
    owner: Pubkey

    # current holder
    holder: Pubkey

    # for how long it can be rented (seconds)
    rent_period: int = 60 * 15  # 15m as a default

    # for how long can the rent get extended when NFT is not actively used
    inactive_period: int = 60 * 60 * 24  # 24h as a default

    # filename->checksum pair
    files: dict[str, str] = dict()

    @classmethod
    def create(cls, *args: typing.Any) -> "Studyunit":
        """factory

        since: 0.0.1
        """
        return cls(*args)
