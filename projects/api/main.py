import base58
import functools
import httpx
import itertools
import json
import operator
import os
import random
import secrets
import shutil
import tempfile
import time
import uuid
import typing
import uvicorn

from asgiref.wsgi import WsgiToAsgi
from base64 import b64encode, b64decode
from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from flask import Flask, Response, redirect, request as req, send_file
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from os.path import exists, join, splitext
from sm_2 import Card, ReviewLog, Scheduler
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts, TokenAccountOpts
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT
from spl.token.constants import TOKEN_2022_PROGRAM_ID
from types import SimpleNamespace as NS
from urllib.parse import urlparse
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from app.buoy import buoy, vault
from app.constants import (
    DATADIR,
    DATABASE,
    RENT_UPFRONT_COSTS_LAMPORTS,
    WORKER_PROCESSES,
)
from app.chain.rpc import TokenAccount, rpc
from app.db import dbm_open_bytes
from app.rating import Rating
from app.studycard import Studycard
from app.user import User
from app.util import F, SESS_KEY

api = Flask("api")
api.config["UPLOADDIR"] = "/opt/skills/static"
api.config["DATADIR"] = DATADIR
api.config["DATABASE"] = DATABASE

headers = NS(
    main={"Content-type": "application/json"},
    cors=dict(
        {
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
            "Access-Control-Allow-Headers": "authorization, content-type, cookie",
            "Access-Control-Allow-Credentials": "true",
        }
    ),
)

headers.full = dict(headers.main, **headers.cors)

CardAddress = typing.NewType("CardAddress", Pubkey)


@dataclass
class Store:
    session: dict[str, dict]
    challenge: dict[str, str]

    @classmethod
    def create(cls):
        return cls(session=dict(), challenge=dict())


mem = Store.create()

## MODS

mods: list[str] = deque(map(lambda _: secrets.token_hex(10), range(0, 10)), maxlen=10)


@functools.lru_cache(maxsize=1)
def mod_index(key: str, ttl: int) -> int:
    global mods
    if key not in mods:
        return -1

    position = mods.index(key)
    mods.append(secrets.token_hex(10))
    return position


## DEFAULTS FOR PRIMARY DB

with dbm_open_bytes(api.config["DATABASE"], "c") as db:
    if "users" not in db:
        db.setdefault("users", {})
        db.setdefault("decks", [])
        db.setdefault("cards", [])
        db.setdefault("ratings", [])
        db.setdefault("processes", [])

## AUTH


@api.route("/api/dev/authn/verify", methods=["POST", "OPTIONS"])
async def verify():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address = req.json.get("address")
    nonce = req.json.get("nonce")
    signature = req.json.get("signature")

    if address is None:
        raise "Address is missing"

    if nonce is None:
        raise "Nonce is missing!"

    if signature is None:
        raise "Signature is missing!"

    stored = mem.challenge[nonce]
    pubkey_b: bytes = bytes(Pubkey.from_string(address))
    challenge_b: bytes = bytes(stored["message"], "utf-8")
    signature_b: bytes = bytes(signature, "utf-8")

    try:
        VerifyKey(pubkey_b).verify(
            base58.b58decode(challenge_b), base58.b58decode(signature_b)
        )
    except BadSignatureError as ex:
        return Response(500, f"Signature invalid! {ex}")

    handle = str(uuid.uuid4())
    stored["address"] = address
    stored["checked_at"] = None
    mem.session[handle] = stored.copy()

    return Response(json.dumps({"handle": handle}), headers=headers.full)


@api.route("/api/dev/authn", methods=["GET"])
async def authenticate():
    handle = req.args.get("handle")

    if handle is None:
        raise "Handle is missing!"

    retrieved = mem.session[handle]
    if retrieved.get("checked_at", None) is not None:
        raise "Handle reuse! Not allowed!"

    mem.session[handle]["checked_at"] = int(time.time())

    same_site = "strict"
    secure = ""
    if True:  # for dev purposes
        same_site = "None"
        secure = "Secure"

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        address = mem.session[handle]["address"]

        user = User(address=address, holding=None)
        db["users"][address] = asdict(user)

    return Response(
        json.dumps({"location": req.referrer, "bearer": handle}), headers=headers.full
    )


@api.route("/api/dev/authn/session", methods=["GET", "OPTIONS"])
async def authenticated():
    time.sleep(random.randint(0, 10) * 0.1)
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    if "Authorization" not in req.headers:
        return Response(
            json.dumps({"failed": "Missing credentials in request"}),
            status=400,
            headers=headers.full,
        )

    session, err = F.resolve_session_from_bearer(req.headers, mem)
    if err is not None or session is None:
        return Response(
            json.dumps({"failed": "Unathorized"}), status=401, headers=headers.full
        )

    return Response(
        json.dumps({"address": session.get("address")}), headers=headers.full
    )


@api.route("/api/dev/authn/challenge", methods=["POST", "OPTIONS"])
async def challenge():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    guid = str(uuid.uuid4())
    challenge = base58.b58encode(
        bytes(f"skills-authn-challenge-{guid}", "utf-8")
    ).decode("utf-8")

    nonce = req.json.get("nonce")
    if nonce is None:
        raise "Missing Nonce argument!"

    mem.challenge[nonce] = dict(cId=guid, message=challenge)

    return Response(json.dumps(mem.challenge[nonce]), headers=headers.full)


## CARDS


@api.route("/api/dev/cards", methods=["GET", "OPTIONS"])
async def list_cards():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    skip, limit, contributor = operator.itemgetter("skip", "limit", "contributor")(
        {**{"skip": 0, "limit": 10, "contributor": None}, **req.args}
    )

    tokens: dict[str, float] = {}

    for token in rpc.client.get_token_accounts_by_owner_json_parsed(
        Pubkey.from_string(address),
        TokenAccountOpts(program_id=TOKEN_2022_PROGRAM_ID),
        commitment="confirmed",
    ).value:
        k = token.account.data.parsed["info"]["mint"]
        v = float(token.account.data.parsed["info"]["tokenAmount"]["amount"])
        tokens[k] = v

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        criteria = {}

        if contributor is not None:
            criteria["contributor"] = contributor

        criteria["contributor"] = address

        matches = list(
            map(operator.methodcaller("copy"), filter(F.where(criteria), db["cards"]))
        )[skip : skip + limit]

        def with_mint(e: dict) -> dict:
            try:
                e["spl"] = json.loads(
                    rpc.client.get_account_info(
                        Pubkey.from_string(e["address"])
                    ).value.to_json()
                )

                data = MINT_LAYOUT.parse(bytes(e["spl"]["data"]))
                e["spl"]["data"] = data
                e["spl"]["data"]["amount"] = tokens.get(e["address"], 0.0)
                e["spl"]["data"]["minter"] = str(Pubkey(data.mint_authority))
                e["spl"]["data"]["freezer"] = str(Pubkey(data.freeze_authority))
                return e
            except Exception as ex:
                print(ex)
                return e

        with_mints = json.dumps(
            list(map(with_mint, matches)),
            default=lambda o: "<can't deserialize>",
        )
        return Response(
            with_mints,
            headers={"Content-Range": f"cards {skip}/{skip+limit}", **headers.full},
        )


@api.route("/api/dev/cards", methods=["POST", "OPTIONS"])
async def card_store() -> CardAddress:
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        contributed = list(
            filter(
                F.where({"access": "free"}),
                filter(F.where({"contributor": address}), db["cards"]),
            )
        )

        front = req.form.get("media_front")
        back = req.form.get("media_back")

        form = dict(req.form)
        form["contributor"] = address

        form.pop("media_front", None)
        form.pop("media_back", None)

        card = Studycard.create(**form)

        for key in req.files:
            if "" == key:
                continue

            f = req.files[key]
            filename = secure_filename(f.filename)
            f.save(join(DATADIR, filename))
            card.media[f.filename] = filename

        # pretend its multiple files
        if front is not None:
            card.front = [card.media[front]]

        if back is not None:
            card.back = [card.media[back]]

        if "free" != card.access and not any(contributed):
            n: int = 1
            # raise Exception(
            #     f"Cannot rent/sell a card before contributing at least {n} for free first"
            # )

        if "rent" == card.access:
            pass  # ??

        db["cards"].append(asdict(card))

        return Response(json.dumps(asdict(card)), headers=headers.full)


@api.route("/api/dev/cards/media/<filename>", methods=["GET", "OPTIONS"])
async def card_media_read(filename: str):
    # if "OPTIONS" == req.method:
    #     return Response("", headers=headers.cors)

    # return send_file(join(DATADIR, secure_filename(filename)))
    raise NotImplementedError


@api.route("/api/dev/cards/choices", methods=["GET", "OPTIONS"])
async def cards_next():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    tokens: dict[str, float] = {}

    for token in rpc.client.get_token_accounts_by_owner_json_parsed(
        buoy.pair.pubkey(),
        TokenAccountOpts(program_id=TOKEN_2022_PROGRAM_ID),
        commitment="confirmed",
    ).value:
        k = token.account.data.parsed["info"]["mint"]
        v = float(token.account.data.parsed["info"]["tokenAmount"]["amount"])
        tokens[k] = v

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _user = next(filter(F.where({"address": address}), db["users"].values()), None)
        assert _user is not None

        user = User(**_user)

        ratings = list(
            map(
                Rating.from_dict,
                filter(F.where({"contributor": user.address}), db["ratings"]),
            )
        )

        user_rated_cards = list(map(operator.attrgetter("card"), ratings))

        relevant = list(
            filter(
                lambda e: e.card in user_rated_cards and e.contributor != user.address,
                map(Rating.from_dict, db["ratings"]),
            )
        )

        grouped = itertools.groupby(db["ratings"], key=operator.itemgetter("card"))
        rated = {}

        for k, v in grouped:
            values = list(map(operator.itemgetter("value"), list(v)))
            if not any(values):
                rated[k] = 1
                continue

            rated[k] = sum(values) / len(values)

        user_skill = user.get_skill(ratings, relevant)

        def with_held_amount(e: dict) -> dict:
            e["spl"] = {"data": {"amount": tokens.get(e["address"], 0.0)}}
            return e

        # find next where
        #   access: rent
        #   rating > user_skill
        #   sm2 due > time
        next_rent = next(
            map(
                with_held_amount,
                map(
                    operator.methodcaller("copy"),
                    filter(
                        lambda e: rated.get(e["identifier"], 0) >= user_skill,
                        filter(F.where({"access": "rent"}), db["cards"]),
                    ),
                ),
            ),
            None,
        )

        # find next where
        #   access: free
        #   rating > user_skill
        #   sm2 due > time
        next_free = next(
            filter(
                lambda e: rated.get(e["identifier"], 0) >= user_skill,
                filter(F.where({"access": "free"}), db["cards"]),
            ),
            None,
        )

        # ?
        picked = None
        _held = next(filter(F.where({"holder": user.address}), db["cards"]), None)

        if _held is not None:
            held = Studycard.create(**_held)
            if held.free_at < int(time.time()):
                picked = held.identifier

        return Response(
            json.dumps({"free": next_free, "rent": next_rent, "picked": picked}),
            headers=headers.full,
        )


@api.route("/api/dev/cards/<card_id>/rent", methods=["GET", "OPTIONS"])
async def get_card_rent_tx(card_id: str):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)

        if _card is None:
            raise Exception(f"Card {card_id} not found!")

        card_idx = db["cards"].index(_card)
        card = Studycard.create(**_card)

        if "rent" != card.access:
            raise Exception(f"This card is free!")

        if card.free_at > int(time.time()):
            remaining = int(time.time()) - card.free_at
            raise Exception(
                f"Card {card_id} is currently reserved! Try again in {remaining}"
            )

        rent_lamports = 99_999  # temporarily hardcoded
        buoy.fund_pair()

        txn_rent_fee = rpc.transfer(
            Pubkey.from_string(address),
            buoy.pair.pubkey(),
            rent_lamports + RENT_UPFRONT_COSTS_LAMPORTS,
        )

        db["cards"][card_idx] = asdict(card)

        return Response(
            json.dumps(
                {
                    "txn_rent_fee": b64encode(bytes(txn_rent_fee)).decode("utf-8"),
                    "cost": rent_lamports,
                }
            ),
            headers=headers.full,
        )


@api.route("/api/dev/cards/pick", methods=["POST", "OPTIONS"])
async def card_pick():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    access_type: str = "free"

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    sig_raw = req.json.get("sig", None)
    card_id = req.json.get("card", None)

    assert card_id is not None

    if sig_raw is not None:
        access_type = "rent"

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _user = next(filter(F.where({"address": address}), db["users"].values()), None)
        assert _user is not None

        # @TODO assert card is not already held by someone else
        _card = next(
            filter(
                F.where({"identifier": card_id, "access": access_type}), db["cards"]
            ),
            None,
        )
        assert _card is not None

        card_idx = db["cards"].index(_card)

        if sig_raw is not None:
            sig = Signature(base58.b58decode(sig_raw))
            tx = rpc.client.get_transaction(
                sig, commitment="confirmed", max_supported_transaction_version=0
            )

            print(["RENT TX: ", tx.value])  # @TODO: verify the transaction

        db["cards"][card_idx]["holder"] = address
        db["cards"][card_idx]["escrow"] = sig_raw
        db["users"][address]["holding"] = card_id

    return Response("{}", headers=headers.full)


async def read_card(card_id, expire: int | None = None):
    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)

        async with httpx.AsyncClient() as c:
            return await c.get(list(card["media"].items())[0][0], follow_redirects=True)


@api.route("/api/dev/cards/<card_id>", methods=["GET", "OPTIONS"])
async def get_card(card_id: str):
    global mods

    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    print(["NEXT TOKEN ", mods[0]])

    mod = -1
    if "authn" in req.cookies:
        ttl: int = int(time.time() / 600)  # 10 minutes
        mod = mod_index(req.cookies.get("authn"), ttl)
        print(["MOD", mod])

    # data: bytes = await read_card(card_id, 15 * 60)
    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)
        card = Studycard.create(**_card)

        if -1 < mod:
            return send_file(
                join(DATADIR, list(card.media.items())[0][0]), "image/jpeg"
            )

        return send_file(join(DATADIR, list(card.content.items())[0][0]), "image/jpeg")


@api.route("/api/dev/cards/<card_id>", methods=["PATCH", "OPTIONS"])
async def verify_card(card_id: str):
    global mods
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    mod = -1
    if "authn" in req.cookies:
        ttl: int = int(time.time() / 600)  # 10 minutes
        mod = mod_index(req.cookies.get("authn"), ttl)

    if 0 > mod:
        raise NotImplementedError

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)
        _card["moderated_at"] = int(time.time())

        return Response("", headers=headers.cors)


## REVIEWS AND RATINGS


@api.route("/api/dev/cards/<card_id>/review/<value>", methods=["PATCH", "OPTIONS"])
async def card_review(card_id: str, value: int):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        if not any(filter(F.where({"identifier": card_id}), db["cards"])):
            raise Exception(f"Card {card_id} not found")

    with dbm_open_bytes(
        F.resolve_reviews_path(api.config["DATABASE"], address), "c"
    ) as db:
        db.setdefault("reviews", [])

        flashcard = next(filter(F.where({"identifier": card_id}), db["reviews"]), None)

        # defaults
        ref = Card()
        flashcard_idx = len(db["reviews"])

        # overwrites
        if flashcard is not None:
            ref = Card.from_dict(flashcard["ref"])
            flashcard_idx = db["reviews"].index(flashcard)

        ref, _ = Scheduler.review_card(ref, int(value), datetime.now(timezone.utc))

        flashcard = dict(flashcard or {}, ref=ref.to_dict())

        if not any(db["reviews"]):
            db["reviews"].append(flashcard)

        db["reviews"][flashcard_idx] = flashcard

    return Response("", headers=headers.cors)


@api.route("/api/dev/cards/<card_id>/rating/<value>", methods=["PATCH", "OPTIONS"])
async def card_rating(card_id: str, value: int):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        if not any(filter(F.where({"identifier": card_id}), db["cards"])):
            raise Exception(f"Card {card_id} not found")

    with dbm_open_bytes(F.resolve_events_path(api.config["DATABASE"]), "c") as db:
        db.setdefault("events", [])

        rating_id = str(uuid.uuid4())

        db["events"].append([rating_id, ":rating/value", value])

        db["events"].append([rating_id, ":rating/by", address])

        db["events"].append([rating_id, ":rating/for", card_id])

    return Response("", headers=headers.cors)


## DECKS
# ...


## MINT

txn_opts = TxOpts(
    skip_preflight=False,
    preflight_commitment=Confirmed,
    skip_confirmation=False,
)


@api.route("/api/dev/token/account/mint/tx", methods=["GET", "OPTIONS"])
async def create_token_mint_account_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    txn_mint_account, mint_account = rpc.create_mint_account(
        Pubkey.from_string(address), vault.pubkey()
    )

    return Response(
        json.dumps(
            {
                "txn": b64encode(bytes(txn_mint_account)).decode("utf-8"),
                "mint_account": str(mint_account.pubkey()),
            }
        ),
        headers=headers.full,
    )


@api.route("/api/dev/token/account/tx", methods=["GET", "OPTIONS"])
async def create_token_account_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    mint_account_pubkey = req.args.get("mint_account")
    assert mint_account_pubkey is not None

    txn_account, token_account = rpc.create_token_account(
        Pubkey.from_string(address),
        Pubkey.from_string(mint_account_pubkey),
    )

    txn_token_escrow, _ = rpc.create_token_account(
        Pubkey.from_string(address),
        Pubkey.from_string(mint_account_pubkey),
        buoy.pair.pubkey(),
    )

    return Response(
        json.dumps(
            {
                "txn": b64encode(bytes(txn_account)).decode("utf-8"),
                "txn_escrows": b64encode(bytes(txn_token_escrow)).decode("utf-8"),
                "token_account": str(token_account.pubkey()),
            }
        ),
        headers=headers.full,
    )


@api.route("/api/dev/token/mint/tx", methods=["GET", "OPTIONS"])
async def mint_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    token_account_pubkey = req.args.get("token_account")
    assert token_account_pubkey is not None

    mint_account_pubkey = req.args.get("mint_account")
    assert mint_account_pubkey is not None

    card_id = req.args.get("card_id")
    assert card_id is not None

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)

        if card is None:
            raise Exception("Card not found!")

        card_idx = db["cards"].index(card)
        db["cards"][card_idx] = dict(
            card, address=mint_account_pubkey, token_account=token_account_pubkey
        )

    txn_mint_to = rpc.mint_to(
        token_account=Pubkey.from_string(token_account_pubkey),
        fee_payer=Pubkey.from_string(address),
        mint=Pubkey.from_string(mint_account_pubkey),
        authority=vault,
    )

    return Response(
        json.dumps({"txn_mint_to": b64encode(bytes(txn_mint_to)).decode("utf-8")}),
        headers=headers.full,
    )


## ESCROW


@api.route("/api/dev/token/escrow/tx", methods=["GET", "OPTIONS"])
async def escrow_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    card_id = req.args.get("card_id")
    assert card_id is not None

    ta_escrow = None

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)
        assert _card is not None

        card = Studycard.create(**_card)

        for token in rpc.client.get_token_accounts_by_owner_json_parsed(
            buoy.pair.pubkey(),
            TokenAccountOpts(program_id=TOKEN_2022_PROGRAM_ID),
            commitment="confirmed",
        ).value:
            if card.mint_account == token.account.data.parsed["info"]["mint"]:
                ta_escrow = TokenAccount(token.pubkey)
                break

        assert ta_escrow is not None

        txn_escrow = rpc.rent_token_escrow(
            fee_payer=Pubkey.from_string(address),
            mint=Pubkey.from_string(card.mint_account),
            source=TokenAccount(Pubkey.from_string(card.token_account)),
            dest=ta_escrow,
            owner=Pubkey.from_string(address),
        )

        return Response(
            json.dumps({"txn_escrow_to": b64encode(bytes(txn_escrow)).decode("utf-8")}),
            headers=headers.full,
        )


@api.route("/api/dev/token/retrieval/tx", methods=["GET", "OPTIONS"])
async def retrieval_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    txn_retrieval = rpc.transfer(Pubkey.from_string(address), buoy.pair.pubkey(), 5_000)

    return Response(
        json.dumps({"txn_retrieval": b64encode(bytes(txn_retrieval)).decode("utf-8")}),
        headers=headers.full,
    )


@api.route("/api/dev/token/retrieve/tx", methods=["GET", "OPTIONS"])
async def retrieve_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    card_id = req.args.get("card_id")
    assert card_id is not None

    ta_escrow = None

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _card = next(filter(F.where({"identifier": card_id}), db["cards"]), None)
        assert _card is not None

        card = Studycard.create(**_card)

        for token in rpc.client.get_token_accounts_by_owner_json_parsed(
            buoy.pair.pubkey(),
            TokenAccountOpts(program_id=TOKEN_2022_PROGRAM_ID),
            commitment="confirmed",
        ).value:
            if card.mint_account == token.account.data.parsed["info"][
                "mint"
            ] and 0 < float(token.account.data.parsed["info"]["tokenAmount"]["amount"]):
                ta_escrow = TokenAccount(token.pubkey)
                break

        assert ta_escrow is not None

        txn_retrieve = rpc.return_token_escrow(
            fee_payer=buoy.pair.pubkey(),
            mint=Pubkey.from_string(card.mint_account),
            source=ta_escrow,
            dest=TokenAccount(Pubkey.from_string(card.token_account)),
            owner=buoy.pair.pubkey(),
        )
        txn_retrieve.signatures = rpc.sign_transaction(txn_retrieve, buoy.pair)
        txn_retrieved = rpc.client.send_transaction(txn_retrieve, txn_opts)

        return Response(
            json.dumps({"ok": 0}),
            headers=headers.full,
        )


expiry_checked_at = int(time.time())


@api.before_request
def rent_expiry():
    global expiry_checked_at

    print(datetime.now())
    address, err = F.resolve_address_from_bearer(req.headers, mem)

    if err is not None:
        return

    if address is None:
        return

    if not address:
        return

    timeout = random.randint(40, 80)
    check_at = expiry_checked_at + timeout

    if check_at > int(time.time()):
        return

    expiry_checked_at = int(time.time())

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        for card_idx, _card in enumerate(db["cards"]):
            card = Studycard.create(**_card)

            if "rent" != card.access:
                continue

            if card.free_at < int(time.time()):
                continue

            raters = []
            rent_lamports = 99_999  # temporarily hardcoded
            buoy.release_rent_escrow(
                rent_lamports,
                Pubkey.from_string(card.contributor),
                raters,
                Pubkey.from_string(card.token_account),
                Pubkey.from_string(card.mint_account),
            )


@api.errorhandler(Exception)
def errors(ex):
    if isinstance(ex, HTTPException):
        return ex

    # return Response(json.dumps(dict(failed=repr(ex))), status=500, headers=headers.cors)
    raise ex


api.register_error_handler(Exception, errors)

a_api = WsgiToAsgi(api)


if __name__ == "__main__":
    # parser = argparse.Parser(prog="", description="", epilog="")
    # parser.add_argument("")

    # args = parse.parse_args()

    for e in ["DATADIR", "UPLOADDIR"]:
        if not exists(api.config[e]):
            os.makedirs(api.config[e])

    with dbm_open_bytes(DATABASE, "c") as db:
        procs = deque(db["processes"], maxlen=WORKER_PROCESSES)
        proc = next(filter(F.where({"pid": os.getpid()}), procs), None)

        if proc is None:
            proc = {"pid": os.getpid(), "started_at": int(time.time())}
            procs.append(proc)

        worker_number = procs.index(proc) + 1
        time.sleep(worker_number * 2)  # let previous worker processes resolve

        db["processes"] = list(procs)

    uvicorn.run(
        "main:a_api", reload=False, workers=WORKER_PROCESSES, host="0.0.0.0", port=5140
    )
