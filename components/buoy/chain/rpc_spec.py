"""?
"""

import json
import operator
import os
import time

from mamba import context, describe, it  # type: ignore[import-untyped]
from expects import contain, expect, equal  # type: ignore[import-untyped]
from os.path import exists
from pprint import pprint as pp
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solders.keypair import Keypair

from app.chain.rpc import RPC, NetLoc  # pylint: disable=import-error

DEVNET_TEST_KEYPAIR = None
KEYPATH = f"""{os.environ["HOME"]}/.config/solana/id.json"""

assert exists(KEYPATH)

with open(KEYPATH, "r") as f:
    DEVNET_TEST_KEYPAIR = json.loads(f.read())

assert DEVNET_TEST_KEYPAIR is not None

rpc = RPC.create(NetLoc("http://127.0.0.1:8899"))

with describe("rpc handler "):
    with context("tokens"):
        with it("can create an NFT and add it to end users pubkey") as self:

            self.expected = 0

            mint_control = Keypair()
            end_user = Keypair.from_bytes(DEVNET_TEST_KEYPAIR)

            print(f"pubkey: {end_user.pubkey()}")

            txn_opts = TxOpts(
                skip_preflight=False,
                preflight_commitment=Confirmed,
                skip_confirmation=False,
            )

            # --A
            txn_mint_account, mint = rpc.create_mint_account(
                end_user.pubkey(), mint_control.pubkey()
            )

            sig_idx = txn_mint_account.message.account_keys.index(end_user.pubkey())
            sigs = txn_mint_account.signatures
            sigs[sig_idx] = end_user.sign_message(bytes(txn_mint_account.message))
            txn_mint_account.signatures = sigs

            res_a = rpc.client.send_transaction(txn_mint_account, txn_opts)

            # --B
            txn_account, token_account = rpc.create_token_account(
                end_user.pubkey(), mint.pubkey()
            )

            sig_idx = txn_account.message.account_keys.index(end_user.pubkey())
            sigs = txn_account.signatures
            sigs[sig_idx] = end_user.sign_message(bytes(txn_account.message))
            txn_account.signatures = sigs

            res_b = rpc.client.send_transaction(txn_account, txn_opts)

            # --C
            txn_mint = rpc.mint_to(
                token_account.pubkey(), end_user.pubkey(), mint.pubkey(), mint_control
            )
            sig_idx = txn_mint.message.account_keys.index(end_user.pubkey())
            sigs = txn_mint.signatures
            sigs[sig_idx] = end_user.sign_message(bytes(txn_mint.message))
            txn_mint.signatures = sigs

            res_d = rpc.client.send_transaction(txn_mint, txn_opts)

            tokens = rpc.get_token_accounts(end_user.pubkey(), "confirmed")
            token_keys = list(map(operator.attrgetter("pubkey"), tokens.value))

            expect(token_keys).to(contain(token_account.pubkey()))

        with it("can freeze and thaw tokens"):
            # freeze a token in user X's possesion
            expect(1).to(equal(2))
