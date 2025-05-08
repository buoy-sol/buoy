"""Solana RPC

"""

import typing

from dataclasses import dataclass
import spl.token.instructions as tokenprog

from solana.rpc.api import Client
from solana.rpc.types import TokenAccountOpts
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders import system_program as sysprog
from solders.message import Message
from solders.null_signer import NullSigner
from solders.transaction import VersionedTransaction
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT
from spl.token.constants import ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.client import Token
from spl.token.instructions import get_associated_token_address


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

    def create_mint_account(
        self, fee_payer: Pubkey, mint_control: Pubkey
    ) -> typing.Tuple[VersionedTransaction, Keypair]:
        """?"""

        mint_keypair = Keypair()
        # mint_control = Pubkey.default()  # None
        decimals = 0

        blockhash = self.client.get_latest_blockhash().value.blockhash
        cost = Token.get_min_balance_rent_for_exempt_for_mint(self.client)

        ixs = [
            sysprog.create_account(
                sysprog.CreateAccountParams(
                    from_pubkey=fee_payer,
                    to_pubkey=mint_keypair.pubkey(),
                    lamports=cost,
                    space=MINT_LAYOUT.sizeof(),
                    owner=TOKEN_2022_PROGRAM_ID,
                )
            ),
            tokenprog.initialize_mint(
                tokenprog.InitializeMintParams(
                    program_id=TOKEN_2022_PROGRAM_ID,
                    mint=mint_keypair.pubkey(),
                    decimals=decimals,
                    mint_authority=mint_control,
                    freeze_authority=mint_control,
                )
            ),
        ]

        msg = Message.new_with_blockhash(ixs, fee_payer, blockhash)
        txn = VersionedTransaction(msg, (NullSigner(fee_payer), mint_keypair))

        return txn, mint_keypair

    def create_token_account(
        self, fee_payer: Pubkey, mint: Pubkey
    ) -> typing.Tuple[VersionedTransaction, Keypair]:
        """?"""
        blockhash = self.client.get_latest_blockhash().value.blockhash
        cost = Token.get_min_balance_rent_for_exempt_for_account(self.client)

        account = Keypair()

        ixs = [
            sysprog.create_account(
                sysprog.CreateAccountParams(
                    from_pubkey=fee_payer,
                    to_pubkey=account.pubkey(),
                    lamports=cost,
                    space=ACCOUNT_LAYOUT.sizeof(),
                    owner=TOKEN_2022_PROGRAM_ID,
                )
            ),
            tokenprog.initialize_account(
                tokenprog.InitializeAccountParams(
                    account=account.pubkey(),
                    mint=mint,
                    owner=fee_payer,
                    program_id=TOKEN_2022_PROGRAM_ID,
                )
            ),
        ]

        msg = Message.new_with_blockhash(ixs, fee_payer, blockhash)
        txn = VersionedTransaction(msg, (NullSigner(fee_payer), account))
        return txn, account

    def create_associated_token_account(
        self, fee_payer: Pubkey, mint: Pubkey
    ) -> VersionedTransaction:
        """?"""

        blockhash = self.client.get_latest_blockhash().value.blockhash

        ixs = [
            tokenprog.create_associated_token_account(
                payer=fee_payer,
                owner=fee_payer,
                mint=mint,
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        ]

        msg = Message.new_with_blockhash(ixs, fee_payer, blockhash)
        txn = VersionedTransaction(msg, [NullSigner(fee_payer)])
        return txn

    def get_associated_token_address(self, owner: Pubkey, mint: Pubkey):
        """?"""
        return get_associated_token_address(owner, mint)

    def get_token_accounts(self, owner: Pubkey, commitment: str):
        return self.client.get_token_accounts_by_owner(
            owner, TokenAccountOpts(program_id=TOKEN_2022_PROGRAM_ID), commitment
        )

    def mint_to(self, to: Pubkey, fee_payer: Pubkey, mint: Pubkey, authority: Keypair):
        """?"""
        blockhash = self.client.get_latest_blockhash().value.blockhash

        ixs = [
            tokenprog.mint_to_checked(
                tokenprog.MintToCheckedParams(
                    program_id=TOKEN_2022_PROGRAM_ID,
                    mint=mint,
                    dest=to,
                    mint_authority=authority.pubkey(),
                    amount=1,
                    decimals=0,
                    signers=[authority.pubkey()],
                )
            )
        ]

        msg = Message.new_with_blockhash(ixs, fee_payer, blockhash)
        txn = VersionedTransaction(msg, [NullSigner(fee_payer), authority])
        return txn

    def freeze_token_account(
        self, target: Pubkey, fee_payer: Pubkey, mint: Pubkey, authority: Keypair
    ):
        """?"""
        blockhash = self.client.get_latest_blockhash().value.blockhash
        ixs = [
            tokenprog.freeze_account(
                tokenprog.FreezeAccountParams(
                    program_id=TOKEN_2022_PROGRAM_ID,
                    account=target,
                    mint=mint,
                    authority=authority.pubkey(),
                    multi_signers=[authority.pubkey()],
                )
            )
        ]

        msg = Message.new_with_blockhash(ixs, fee_payer, blockhash)
        txn = VersionedTransaction(msg, [NullSigner(fee_payer), authority])
        return txn

    def transfer(self, sender: Keypair, receiver: Pubkey, lamports: int) -> typing.Any:
        """?"""

        blockhash = self.client.get_latest_blockhash().value.blockhash
        ixs = [
            sysprog.transfer(
                sysprog.TransferParams(
                    from_pubkey=sender.pubkey(), to_pubkey=receiver, lamports=lamports
                )
            )
        ]

        msg = Message.new_with_blockhash(ixs, sender.pubkey(), blockhash)
        txn = VersionedTransaction(msg, [sender])
        return txn


rpc = RPC.create(
    NetLoc("http://127.0.0.1:8899")
)  # "https://api.devnet.solana.com"))  # singleton
