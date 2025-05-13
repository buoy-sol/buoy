from dataclasses import dataclass


@dataclass
class Deck:

    @classmethod
    def create(cls):
        return cls()
