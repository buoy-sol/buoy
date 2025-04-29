import base58
import json
import operator
import os
import random
import time
import uuid
import typing
import uvicorn

from asgiref.wsgi import WsgiToAsgi
from dataclasses import dataclass
from flask import Flask, Response, redirect, request as req
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from os.path import exists
from solders.pubkey import Pubkey
from types import SimpleNamespace as NS
from urllib.parse import urlparse
from werkzeug.utils import secure_filename

from app.chain.rpc import rpc
from app.skills.services.study import Studyunit

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

ErrorResult = typing.NewType("ErrorResult", str)
UnitAddress = typing.NewType("UnitAddress", Pubkey)


class F:

    @staticmethod
    def bytes_to_str(e: bytes) -> str:
        return e.decode("utf-8")

    @staticmethod
    def where(criteria: dict[str, typing.Any]) -> typing.Any:
        def inner(e: dict) -> bool:
            ok = True

            for k, v in criteria.items():
                if k not in e:
                    raise KeyError(k)

                matched = e.get(k) == v
                if not matched:
                    ok = False

            return ok

        return inner

    @staticmethod
    def resolve_address_from_cookies(
        cookies: dict,
    ) -> typing.Tuple[str | None, ErrorResult]:
        if SESS_KEY not in cookies:
            return None, "Missing credentials in request"

        handle = req.cookies.get(SESS_KEY)
        retrieved = mem.session.get(handle, None)
        if retrieved is None:
            return None, "Unathorized"

        if "address" not in retrieved:
            return None, "Corrupted session data"

        return retrieved["address"], None


@dataclass
class Store:
    session: dict[str, dict]
    challenge: dict[str, str]

    @classmethod
    def create(cls):
        return cls(session=dict(), challenge=dict())


mem = Store.create()
SESS_KEY = "solana:session"

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


@api.route("/api/dev/unit", methods=["POST", "OPTIONS"])
async def store() -> UnitAddress:
    if "OPTIONS" == req.method:
        return Response("", headers=headers.cors)

    address, err = F.resolve_address_from_cookies(req.cookies)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    with dbm.open(api.config["DATABASE"]) as db:
        contributed = list(
            filter(
                F.where(dict(access="free")),
                map(json.loads, map(F.bytes_to_str, db["users"][address]["units"])),
            )
        )

        unit = Studyunit(**req.json)

        if "free" != unit.access and not any(contributed):
            n: int = 1
            raise Exception(
                f"Cannot rent/sell a unit before contributing at least {n} for free first"
            )

        db.setdefault("users", {})
        db["users"].setdefault(address, {})
        db["users"][address].setdefault("units", {})

        if "rent" == unit.access:
            rpc.get_mint_account()
            rpc.create_token_account()
            rpc.create_associated_token_account()

        db["users"][address]["units"][unit.address] = bytes(
            json.dumps(asdict(unit)), "utf-8"
        )

        return unit.address
        # make an NFT


@api.route("/api/dev/unit/media", methods=["POST", "OPTIONS"])
def media_upload() -> UnitAddress:

    address, err = F.resolve_address_from_cookies(req.cookies)

    if err is not None:
        return Response(json.dumps({"failed": err}), status=400, headers=headers.full)

    # verify

    if "unit" not in req.json:
        raise Exception("Missing unit address in media upload request")

    with dbm.open(api.config["DATABASE"], "c") as db:
        unit_ref: UnitAddress = UnitAddress(req.json["unit"])

        if unit_ref not in db["users"][address]["units"]:
            raise Exception("Given unit does not exist!")

        unit: Studyunit = Studyunit(**db["users"][address]["units"][unit_ref])

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

    return unit.address


@api.errorhandler(Exception)
def errors(ex):
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
