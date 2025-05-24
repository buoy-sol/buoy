import typing

from solders.pubkey import Pubkey


class Rating(typing.NamedTuple):
    """?

    deprecated
    """

    # who made the rating
    contributor: Pubkey

    # card reference
    card: str

    # literally just 1 to 10
    value: float

    # unix timestamp
    timestamp: int

    @classmethod
    def from_dict(cls, data: dict) -> "Rating":
        return cls(**data)
