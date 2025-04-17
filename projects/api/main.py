import asyncio
import base58
import json
import uuid

from flask import Flask, Response, request as req
from hypercorn.config import Config
from hypercorn.asyncio import serve

api = Flask("api")
cors = {
    "Access-Control-Allow-Origin": "http://localhost:5173",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    "Access-Control-Allow-Headers": "*",
}


@api.route("/api/dev/authn", methods=[])
async def sign_in():
    if "OPTIONS" == req.method:
        return Response("", headers=cors)

    return Response(json.dumps(dict(message="!")), headers=cors)


@api.route("/api/dev/authn/challenge", methods=["POST", "OPTIONS"])
async def challenge():
    if "OPTIONS" == req.method:
        return Response("", headers=cors)

    guid = str(uuid.uuid4())
    challenge = base58.b58encode(
        bytes(f"skills-authn-challenge-{guid}", "utf-8")
    ).decode("utf-8")

    return Response(json.dumps(dict(message=challenge, cId=1235)), headers=cors)


if __name__ == "__main__":
    config = Config()
    config.bind = ["localhost:5140"]
    config.use_reloader = True

    asyncio.run(serve(api, config))
