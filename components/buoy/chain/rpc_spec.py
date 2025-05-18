"""?
"""

import json
import operator
import os
import time

from mamba import context, describe, it  # type: ignore[import-untyped]
from expects import contain, expect, equal, be_above  # type: ignore[import-untyped]
from os.path import exists
from pprint import pprint as pp
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solders.keypair import Keypair

from app.chain.rpc import RPC, NetLoc, TokenAccount  # pylint: disable=import-error

DEVNET_TEST_KEYPAIR = None
KEYPATH = f"""{os.environ["HOME"]}/.config/solana/id.json"""

assert exists(KEYPATH)

with open(KEYPATH, "r") as f:
    DEVNET_TEST_KEYPAIR = json.loads(f.read())

assert DEVNET_TEST_KEYPAIR is not None

rpc = RPC.create(NetLoc("http://127.0.0.1:8899"))


txn_opts = TxOpts(
    skip_preflight=False,
    preflight_commitment=Confirmed,
    skip_confirmation=False,
)


with describe("rpc handler "):
    with context("tokens"):
        with it("can create an NFT and add it to end users pubkey") as self:

            self.expected = 0

            mint_control = Keypair()
            end_user = Keypair.from_bytes(DEVNET_TEST_KEYPAIR)

            print(f"pubkey: {end_user.pubkey()}")

            # make a mint accont
            txn_mint_account, mint = rpc.create_mint_account(
                end_user.pubkey(), mint_control.pubkey()
            )
            txn_mint_account.signatures = rpc.sign_transaction(
                txn_mint_account, end_user
            )
            res_a = rpc.client.send_transaction(txn_mint_account, txn_opts)

            # make a token account
            txn_account, token_account = rpc.create_token_account(
                end_user.pubkey(), mint.pubkey()
            )
            txn_account.signatures = rpc.sign_transaction(txn_account, end_user)
            res_b = rpc.client.send_transaction(txn_account, txn_opts)

            # mint to payer
            txn_mint = rpc.mint_to(
                token_account.pubkey(), end_user.pubkey(), mint.pubkey(), mint_control
            )
            txn_mint.signatures = rpc.sign_transaction(txn_mint, end_user)
            res_c = rpc.client.send_transaction(txn_mint, txn_opts)

            tokens = rpc.get_token_accounts(end_user.pubkey(), "confirmed")
            token_keys = list(map(operator.attrgetter("pubkey"), tokens.value))

            expect(token_keys).to(contain(token_account.pubkey()))

        with it("can mint and transfer tokens to and from escrow"):
            # freeze a token in user X's possesion

            buoy = Keypair()

            mint_control = Keypair()
            end_user = Keypair.from_bytes(DEVNET_TEST_KEYPAIR)

            rpc.client.request_airdrop(
                buoy.pubkey(), 99999, commitment="confirmed"
            )  # ??? does not work?
            rpc.client.request_airdrop(end_user.pubkey(), 99999, commitment="confirmed")
            print(f"end user pubkey: {end_user.pubkey()}")

            txn_opts = TxOpts(
                skip_preflight=False,
                preflight_commitment=Confirmed,
                skip_confirmation=False,
            )

            print(["BALANCE ", rpc.client.get_balance(buoy.pubkey()).value])  # ?????

            # make a mint
            txn_mint_account, mint = rpc.create_mint_account(
                end_user.pubkey(), mint_control.pubkey()
            )
            txn_mint_account.signatures = rpc.sign_transaction(
                txn_mint_account, end_user
            )
            txn_mint_account_res = rpc.client.send_transaction(
                txn_mint_account, txn_opts
            )

            # make token account
            txn_account, token_account = rpc.create_token_account(
                end_user.pubkey(), mint.pubkey()
            )
            txn_account.signatures = rpc.sign_transaction(txn_account, end_user)
            txn_account_res = rpc.client.send_transaction(txn_account, txn_opts)

            # mint to payer
            txn_mint = rpc.mint_to(
                token_account.pubkey(), end_user.pubkey(), mint.pubkey(), mint_control
            )
            txn_mint.signatures = rpc.sign_transaction(txn_mint, end_user)
            txn_mint_res = rpc.client.send_transaction(txn_mint, txn_opts)

            # make another token account
            txn_token_escrow, escrow_account = rpc.create_token_account(
                end_user.pubkey(), mint.pubkey(), buoy.pubkey()
            )
            txn_token_escrow.signatures = rpc.sign_transaction(
                txn_token_escrow, end_user
            )
            res_d = rpc.client.send_transaction(txn_token_escrow, txn_opts)

            # transfer from token account to another
            ta_escrow = TokenAccount.create(escrow_account.pubkey())
            ta_end_user = TokenAccount.create(token_account.pubkey())

            txn_rent = rpc.rent_token_escrow(
                fee_payer=end_user.pubkey(),
                mint=mint.pubkey(),
                source=ta_end_user,
                dest=ta_escrow,
                owner=end_user.pubkey(),
            )
            txn_rent.signatures = rpc.sign_transaction(txn_rent, end_user)

            token_rent = rpc.client.send_transaction(txn_rent, txn_opts)
            tokens = rpc.client.get_token_account_balance(ta_escrow.value, "confirmed")
            expect(int(tokens.value.amount)).to(be_above(0))
