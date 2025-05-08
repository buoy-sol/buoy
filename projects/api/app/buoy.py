import math
import os
import typing

from dataclasses import dataclass, field
from os.path import exists
from solana.rpc.types import TxOpts
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from app.chain.rpc import rpc

PAIR_PATH = "/var/tmp/buoy.pair"  # @TODO: CYCLE
VAULT_PATH = "/var/tmp/vault.pair"  # @TODO: CYCLE

with open(VAULT_PATH, "r") as f:
    vault: Keypair = Keypair.from_base58_string(f.read().rstrip())

assert vault is not None

rpc.client.request_airdrop(vault.pubkey(), 999_999_999)


class Distribution(typing.NamedTuple):
    contributor: int = 60
    vault: int = 5
    rater: int = 1


@dataclass
class Buoy:

    # handle for rent transactions
    pair: Keypair

    @classmethod
    def create(cls):
        pair: Keypair = None

        if not exists(PAIR_PATH):
            pair = Keypair()

            with open(PAIR_PATH, "w") as f:
                f.write(str(pair))

        if pair is None:
            with open(PAIR_PATH, "r") as f:
                pair = Keypair.from_base58_string(f.read())

        assert pair is not None
        return cls(pair)

    def fund_pair(self):
        """move some funds from vault account to buoy account"""
        cost: int = rpc.client.get_minimum_balance_for_rent_exemption(0).value
        tx = rpc.transfer(vault, self.pair.pubkey(), cost)
        print(
            rpc.client.send_transaction(
                bytes(tx),
                opts=TxOpts(
                    skip_preflight=False,
                    preflight_commitment="confirmed",
                    skip_confirmation=False,
                ),
            )
        )

    def cut(self, percent: int | float, of: int) -> int:
        return math.floor(percent * of / 100)

    def route_unit_rent(
        self,
        lamports: int,
        contributor: Pubkey,
        raters: list[Pubkey],
        distribution: Distribution = None,
    ):
        if distribution is None:  # default distribution
            distribution = Distribution()

        reserved: list[int] = []
        recipients: list[typing.Tuple[Pubkey, int]] = []

        for_vault: int = self.cut(distribution.vault, of=lamports)
        recipients.append((vault.pubkey(), for_vault))
        reserved.append(for_vault)

        for_contributor: int = self.cut(distribution.contributor, of=lamports)
        recipients.append((contributor, for_contributor))
        reserved.append(for_contributor)

        for rater in raters:
            for_rater: int = self.cut(distribution.rater, of=lamports)

            if lamports > sum(reserved):
                recipients.append((rater, for_rater))
                reserved.append(for_rater)

        for recipient, amount in recipients:
            tx = rpc.transfer(self.pair, recipient, amount)
            print(tx)

        return True


buoy = Buoy.create()  # singleton
