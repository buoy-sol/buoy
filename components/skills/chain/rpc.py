"""Solana RPC

"""

import typing

from dataclasses import dataclass

from solana.rpc.api import Client
from solders.pubkey import Pubkey
from spl.token.client import Token


NetLoc = typing.NewType("NetLoc", str)
AccountType = typing.Literal["mint", "token", "associated_token"]


@dataclass
class RPC:
    """?"""

    network: NetLoc
    client: Client

    @classmethod
    def create(cls, network: NetLoc) -> "RPC":
        """?"""
        return cls(network, Client(network))

    def get_mint_account(self) -> typing.Any:
        """returns a mint-account

        since: ?
        """
        return None

    def create_mint_account(self) -> typing.Any:
        """?"""

    def get_token_account(self) -> typing.Any:
        """?"""

    def create_token_account(self) -> typing.Any:
        """?"""

    def get_associated_token_account(self) -> typing.Any:
        """?"""

    def create_associated_token_account(self) -> typing.Any:
        """?"""

    def transfer(self) -> typing.Any:
        """?"""


rpc = RPC.create(NetLoc("https://api.devnet.solana.com"))  # singleton
