import dbm
import json
import typing

from dataclasses import asdict
from contextlib import contextmanager

from app.studyunit import Studyunit

DB_KEY = "lolwhatever"
SYS_USR = "sysusr"


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
            loaded["users"][SYS_USR] = {"address": "nil"}

            loaded["units"] = [
                asdict(
                    Studyunit(
                        **dict(
                            address="nil",
                            contributor=SYS_USR,
                            owner=SYS_USR,
                            holder=SYS_USR,
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
                            address="nil",
                            contributor=SYS_USR,
                            owner=SYS_USR,
                            holder=SYS_USR,
                            access="free",
                            files={
                                "https://picsum.photos/id/175/2896/1944": "a-checksum-here"
                            },
                        )
                    )
                ),
            ]

        yield loaded

        changed = loaded
        db[DB_KEY] = bytes(json.dumps(changed), "utf-8")
