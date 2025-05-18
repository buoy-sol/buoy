import math
import os
import time
import typing

from dataclasses import dataclass, field
from collections import deque
from os.path import exists
from solana.constants import LAMPORTS_PER_SOL
from solana.rpc.types import TxOpts
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from app.chain.rpc import rpc

PAIR_PATH = "/var/tmp/buoy.pair"  # @TODO: CYCLE
VAULT_PATH = "/var/tmp/vault.pair"  # @TODO: CYCLE

with open(VAULT_PATH, "r") as f:
    vault: Keypair = Keypair.from_base58_string(f.read().rstrip())

assert vault is not None

vault_balance: int = rpc.client.get_balance(vault.pubkey()).value
vault_balance_SOL: float = vault_balance / LAMPORTS_PER_SOL

print(["Vault address", vault.pubkey()])
print(["Vault balance SOL", vault_balance_SOL])

if 0.01 > vault_balance_SOL:
    time.sleep(5)
    print(rpc.client.request_airdrop(vault.pubkey(), 1).value)


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
                pair = Keypair.from_base58_string(f.read().rstrip())

        assert pair is not None
        print(pair.pubkey())
        return cls(pair)

    def fund_pair(self):
        """move some funds from vault account to buoy account"""
        balance = rpc.client.get_balance(self.pair.pubkey()).value
        if 0 < balance:
            print("buoy pair already initialized")
            return None

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

    def release_rent_escrow(
        self,
        lamports: int,
        contributor: Pubkey,
        raters: list[Pubkey],
        token_account: Pubkey,
        mint: Pubkey,
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

        # @todo tx has to be funded and signed
        # rpc.return_token_escrow(self.pair, contributor, token_account, mint)

        return True


buoy = Buoy.create()  # singleton
