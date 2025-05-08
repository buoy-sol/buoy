import dbm
import json
import time
import typing

from dataclasses import asdict
from contextlib import contextmanager
from solders.keypair import Keypair

from app.studyunit import Studyunit
from app.buoy import vault

DB_KEY = "lolwhatever"
SYS_USR = "nil"


@contextmanager
def dbm_open_bytes(path: str, mode: str) -> typing.Generator:
    with dbm.open(path, mode) as db:
        if DB_KEY not in db:
            db[DB_KEY] = "{}"

        loaded = json.loads(db[DB_KEY].decode("utf-8"))

        loaded.setdefault("users", {})
        loaded.setdefault("units", [])
        loaded.setdefault("ratings", [])

        if SYS_USR not in loaded["users"]:
            loaded["users"][SYS_USR] = {"address": "nil", "holding": None}

            loaded["units"] = [
                asdict(
                    Studyunit(
                        **dict(
                            address="x1",
                            contributor=str(vault.pubkey()),  # HARDCODED
                            owner="nil",
                            holder=None,
                            access="free",
                            files={
                                "https://picsum.photos/id/77/1631/1102": "some-checksum-here"
                            },
                        )
                    )
                ),
                asdict(
                    Studyunit(
                        **dict(
                            address="x2",
                            contributor=str(vault.pubkey()),  # HARDCODED
                            owner="nil",
                            holder=None,
                            access="rent",
                            files={
                                "https://picsum.photos/id/175/2896/1944": "a-checksum-here"
                            },
                        )
                    )
                ),
            ]

            loaded["ratings"] = [
                {
                    "unit": "x1",
                    "value": 5.5,
                    "contributor": "nil",
                    "timestamp": int(time.time()),
                },
                {
                    "unit": "x2",
                    "value": 9.5,
                    "contributor": "nil",
                    "timestamp": int(time.time()),
                },
                {
                    "unit": "x1",
                    "value": 7.5,
                    "contributor": "user-A",
                    "timestamp": int(time.time()),
                },
                {
                    "unit": "x1",
                    "value": 8.5,
                    "contributor": "user-B",
                    "timestamp": int(time.time()),
                },
            ]

        yield loaded

        changed = loaded
        db[DB_KEY] = bytes(json.dumps(changed), "utf-8")
