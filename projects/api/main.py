import base58
import functools
import httpx
import itertools
import json
import operator
import os
import random
import time
import uuid
import typing
import uvicorn

from asgiref.wsgi import WsgiToAsgi
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from flask import Flask, Response, redirect, request as req
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from os.path import exists
from solders.pubkey import Pubkey
from types import SimpleNamespace as NS
from urllib.parse import urlparse
from werkzeug.utils import secure_filename

from app.chain.rpc import rpc
from app.db import dbm_open_bytes
from app.rating import Rating
from app.studyunit import Studyunit
from app.user import User
from app.util import F, SESS_KEY

api = Flask("api")
api.config["UPLOAD_FOLDER"] = "/opt/skills/static"
api.config["DATA_FOLDER"] = "/opt/skills/dat"
api.config["DATABASE"] = "/opt/skills/dat/db"

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

UnitAddress = typing.NewType("UnitAddress", Pubkey)


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


## UNITS


@api.route("/api/dev/units", methods=["POST", "OPTIONS"])
async def unit_store() -> UnitAddress:
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm_open_bytes(api.config["DATABASE"]) as db:
        contributed = list(
            filter(
                F.where({"access": "free"}),
                filter(F.where({"contributor": address}), db["units"]),
            )
        )

        unit = Studyunit(**req.json)

        if "free" != unit.access and not any(contributed):
            n: int = 1
            raise Exception(
                f"Cannot rent/sell a unit before contributing at least {n} for free first"
            )

        if "rent" == unit.access:
            # make an NFT
            rpc.get_mint_account()
            rpc.create_token_account()
            rpc.create_associated_token_account()

        db["units"].append(bytes(asdict(unit)))

        return unit.address


@api.route("/api/dev/units/media", methods=["POST", "OPTIONS"])
def unit_media_upload() -> UnitAddress:

    address, err = F.resolve_address_from_cookies(req.cookies, mem)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    # verify

    if "unit" not in req.json:
        raise Exception("Missing unit address in media upload request")

    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        unit_ref: UnitAddress = UnitAddress(req.json["unit"])
        unit: StudyUnit | None = next(
            filter(F.where({"address": unit_ref}), db["units"]), None
        )

        if unit is None:
            raise Exception("Given unit does not exist!")

        unit_idx: int = db["units"].index(unit)
        f = request.files

        for e, data in request.files:
            if data is None:
                # @todo log
                continue

            if data.filename is None:
                # @todo log
                continue

            if "" == data.filename:
                # @todo log
                continue

            filename: str = secure_filename(data.filename)

            stem, ext = splitext(filename)
            storename: str = ".".join([hashlib.sha256(data).hexdigest(), ext])

            data.seek(0)
            data.save(join(api.config["UPLOAD_FOLDER"], filename))

            unit.files[filename] = {"stored": storename}

        db["units"][unit_idx] = unit

    return unit.address


@api.route("/api/dev/units", methods=["GET", "OPTIONS"])
async def units_next():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    # address, err = F.resolve_address_from_cookies(req.cookies, mem)

    # if err is not None:
    #     return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    address = "nil"  # temporary!

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

        user_rated_units = list(map(operator.attrgetter("unit"), ratings))

        relevant = list(
            filter(
                lambda e: e.unit in user_rated_units and e.contributor != user.address,
                map(Rating.from_dict, db["ratings"]),
            )
        )

        grouped = itertools.groupby(db["ratings"], key=operator.itemgetter("unit"))
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
                filter(F.where({"access": "rent"}), db["units"]),
            ),
            None,
        )

        # find next where access: free and rating > user_skill
        next_free = next(
            filter(
                lambda e: rated.get(e["address"], 0) >= user_skill,
                filter(F.where({"access": "free"}), db["units"]),
            ),
            None,
        )

        return Response(
            json.dumps({"free": next_free, "rent": next_rent, "picked": user.holding}),
            headers=headers.full,
        )


@api.route("/api/dev/units/pick", methods=["POST", "OPTIONS"])
async def unit_pick():
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address = "nil"  # temporary!
    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        _user = next(filter(F.where({"address": address}), db["users"].values()), None)
        assert _user is not None

        db["users"][address]["holding"] = req.json.get("unit")

    return Response("{}", headers=headers.full)


async def read_unit(unit_id, expire: int | None = None):
    with dbm_open_bytes(api.config["DATABASE"], "c") as db:
        unit = next(filter(F.where({"address": unit_id}), db["units"]), None)

        assert unit is not None
        async with httpx.AsyncClient() as c:
            return await c.get(list(unit["files"].items())[0][0], follow_redirects=True)


@api.route("/api/dev/units/<unit_id>.<ext>", methods=["GET", "OPTIONS"])
async def get_unit(unit_id: str, ext: str):
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    data: bytes = await read_unit(unit_id, 15 * 60)
    content_type = {"Content-type": "image/jpeg"}
    return Response(data.content, headers=dict(headers.cors, **content_type))


@api.errorhandler(Exception)
def errors(ex):
    raise ex
    return Response(json.dumps(dict(failed=repr(ex))), status=500, headers=headers.cors)


api.register_error_handler(Exception, errors)

a_api = WsgiToAsgi(api)


if __name__ == "__main__":
    # parser = argparse.Parser(prog="", description="", epilog="")
    # parser.add_argument("")

    # args = parse.parse_args()

    for e in ["DATA_FOLDER", "UPLOAD_FOLDER"]:
        if not exists(api.config[e]):
            os.makedirs(api.config[e])

    uvicorn.run("main:a_api", reload=False, port=5140)
