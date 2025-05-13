import base58
import functools
import httpx
import itertools
import json
import operator
import os
import random
import shutil
import tempfile
import time
import uuid
import typing
import uvicorn

from asgiref.wsgi import WsgiToAsgi
from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from flask import Flask, Response, redirect, request as req, send_file
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from os.path import exists, join, splitext
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders import VersionedTransaction
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT
from spl.token.constants import TOKEN_2022_PROGRAM_ID
from types import SimpleNamespace as NS
from urllib.parse import urlparse
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from app.buoy import buoy, vault
from app.constants import WORKER_PROCESSES, DATADIR, DATABASE
from app.chain.rpc import rpc
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
            "Access-Control-Allow-Headers": "*",
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
    if True:  # for dev purposes
        same_site = "Lax"

    with_cookie = dict(
        headers.cors,
        **{
            "Set-Cookie": f"""{SESS_KEY}={handle}; path=/; HttpOnly; SameSite={same_site}"""
        },
    )

    with_redirect = dict(with_cookie, **{"Location": req.referrer})

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        address = mem.session[handle]["address"]

        user = User(address=address, holding=None)
        db["users"][address] = asdict(user)

    return Response(status=302, headers=with_redirect)


@api.route("/api/dev/authn/session", methods=["GET", "OPTIONS"])
async def authenticated():
    time.sleep(random.randint(0, 10) * 0.1)
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    if SESS_KEY not in req.cookies:
        return Response(
            json.dumps({"failed": "Missing credentials in request"}),
            status=400,
            headers=headers.full,
        )

    handle = req.cookies.get(SESS_KEY)
    retrieved = mem.session.get(handle, None)
    if retrieved is None:
        return Response(
            json.dumps({"failed": "Unathorized"}), status=401, headers=headers.full
        )

    return Response(json.dumps(retrieved), headers=headers.full)


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

    skip, limit, contributor = operator.itemgetter("skip", "limit", "contributor")(
        {**{"skip": 0, "limit": 10, "contributor": None}, **req.args}
    )

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        criteria = {}

        if contributor is not None:
            criteria["contributor"] = contributor

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

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        contributed = list(
            filter(
                F.where({"access": "free"}),
                filter(F.where({"contributor": address}), db["cards"]),
            )
        )

        print(req.form, req.files)

        front = req.form.get("media_front")
        back = req.form.get("media_back")

        form = dict(req.form)

        form.pop("media_front", None)
        form.pop("media_back", None)

        card = Studycard(**form)

        for key in req.files:
            if "" == key:
                continue

            f = req.files[key]
            filename = secure_filename(f.filename)
            f.save(join(DATADIR, filename))
            card.media[f.filename] = filename

        print(card.media)
        # pretend its multiple files
        if front is not None:
            card.front = [card.media[front]]

        if back is not None:
            card.back = [card.media[back]]

        if "free" != card.access and not any(contributed):
            n: int = 1
            raise Exception(
                f"Cannot rent/sell a card before contributing at least {n} for free first"
            )

        if "rent" == card.access:
            pass  # ??

        db["cards"].append(asdict(card))

        return card.address


@api.route("/api/dev/cards/media/<filename>", methods=["GET", "OPTIONS"])
async def card_media_read(filename: str):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    return send_file(join(DATADIR, secure_filename(filename)))


@api.route("/api/dev/cards/choices", methods=["GET", "OPTIONS"])
async def cards_next():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

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

        # find next where access: rent and rating > user_skill
        next_rent = next(
            filter(
                lambda e: rated.get(e["address"], 0) >= user_skill,
                filter(F.where({"access": "rent"}), db["cards"]),
            ),
            None,
        )

        # find next where access: free and rating > user_skill
        next_free = next(
            filter(
                lambda e: rated.get(e["address"], 0) >= user_skill,
                filter(F.where({"access": "free"}), db["cards"]),
            ),
            None,
        )

        # ?
        picked = None
        _held = next(filter(F.where({"holder": user.address}), db["cards"]), None)

        if _held is not None:
            held = Studycard(**_held)
            if held.free_at < int(time.time()):
                picked = held.address

        return Response(
            json.dumps({"free": next_free, "rent": next_rent, "picked": picked}),
            headers=headers.full,
        )


@api.route("/api/dev/cards/<card_id>/rent", methods=["GET", "OPTIONS"])
async def get_card_rent(card_id: str):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _card = next(filter(F.where({"address": card_id}), db["cards"]), None)

        if _card is None:
            raise Exception(f"Card {card_id} not found!")

        card = Studycard(**_card)

        if "rent" != card.access:
            raise Exception(f"This card is free!")

        if card.free_at > int(time.time()):
            remaining = int(time.time()) - card.free_at
            raise Exception(
                f"Card {card_id} is currently reserved! Try again in {remaining}"
            )

        rent_lamports = 999_999  # temporarily hardcoded
        buoy.fund_pair()

        return Response(
            json.dumps({"account": str(buoy.pair.pubkey()), "lamports": rent_lamports}),
            headers=headers.full,
        )


@api.route("/api/dev/cards/pick", methods=["POST", "OPTIONS"])
async def card_pick():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    access_type: str = "free"

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    sig_raw = req.json.get("sig", None)
    card_id = req.json.get("card", None)

    assert card_id is not None

    if sig_raw is not None:
        access_type = "rent"
        sig = Signature(base58.b58decode(sig_raw))
        tx = rpc.client.get_transaction(sig, commitment="confirmed")

        print(tx.value)  # @TODO: verify the transaction

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _user = next(filter(F.where({"address": address}), db["users"].values()), None)
        assert _user is not None

        # @TODO assert card is not already held by someone else
        _card = next(
            filter(F.where({"address": card_id, "access": access_type}), db["cards"]),
            None,
        )
        assert _card is not None

        card_idx = db["cards"].index(_card)
        card = Studycard(**_card)

        if sig_raw is None:
            raters = []

            rent_lamports = 999_999  # temporarily hardcoded
            buoy.route_card_rent(
                rent_lamports, Pubkey.from_string(card.contributor), raters
            )

        db["cards"][card_idx]["holder"] = address
        db["users"][address]["holding"] = req.json.get("card")

    return Response("{}", headers=headers.full)


async def read_card(card_id, expire: int | None = None):
    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        card = next(filter(F.where({"address": card_id}), db["cards"]), None)

        assert card is not None
        async with httpx.AsyncClient() as c:
            return await c.get(list(card["files"].items())[0][0], follow_redirects=True)


@api.route("/api/dev/cards/<card_id>.<ext>", methods=["GET", "OPTIONS"])
async def get_card(card_id: str, ext: str):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    data: bytes = await read_card(card_id, 15 * 60)
    content_type = {"Content-type": "image/jpeg"}
    return Response(data.content, headers=dict(headers.cors, **content_type))


# DECKS
# ...


# MINT

txn_opts = TxOpts(
    skip_preflight=False,
    preflight_commitment=Confirmed,
    skip_confirmation=False,
)


@api.route("/api/dev/token/account/mint/tx", methods=["POST", "OPTIONS"])
async def create_token_mint_account_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    txn_mint_account, mint_account = rpc.create_mint_account(
        Pubkey.from_string(address), vault.pubkey()
    )

    return txn_mint_account.to_json()


@api.route("/api/dev/token/account/mint", methods=["POST", "OPTIONS"])
async def create_token_mint_account():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    txn = VersionedTransaction.from_json(req.json("txn"))
    return Response(
        json.dumps(rpc.client.send_transaction(txn, txn_opts).value),
        headers=headers.full,
    )


@api.route("/api/dev/token/account/tx", methods=["POST", "OPTIONS"])
async def create_token_account_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    txn_account, token_account = rpc.create_token_account(
        Pubkey.from_string(address), mint_account.pubkey()
    )

    return txn_account.to_json()


@api.route("/api/dev/token/account", methods=["POST", "OPTIONS"])
async def create_token_account():
    """?

    @todo once completed, unify with create_mint_account - it's identical code
    """
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    txn = VersionedTransaction.from_json(req.json("txn"))
    return Response(
        json.dumps(rpc.client.send_transaction(txn, txn_opts).value),
        headers=headers.full,
    )


@api.route("/api/dev/token/mint/tx", methods=["POST", "OPTIONS"])
async def mint_tx():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    txn_mint = rpc.mint_to(
        token_account.pubkey(),
        Pubkey.from_string(address),
        mint_account.pubkey(),
        vault,
    )

    return txn_mint.to_json()


@api.route("/api/dev/token/mint", methods=["POST", "OPTIONS"])
async def mint():
    """?

    @todo once completed, unify with create_mint_account - it's identical code
    """
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    txn = VersionedTransaction.from_json(req.json("txn"))
    return Response(
        json.dumps(rpc.client.send_transaction(txn, txn_opts).value),
        headers=headers.full,
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

    uvicorn.run("main:a_api", reload=False, workers=WORKER_PROCESSES, port=5140)
