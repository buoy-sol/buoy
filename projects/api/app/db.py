import dbm
import json
import typing

from contextlib import contextmanager


DB_KEY = "lolwhatever"
SYS_USR = "nil"


@contextmanager
def dbm_open_bytes(path: str, mode: str) -> typing.Generator:
    with dbm.open(path, mode) as db:
        if DB_KEY not in db:
            db[DB_KEY] = "{}"

        loaded = json.loads(db[DB_KEY].decode("utf-8"))

        loaded.setdefault("users", {})
        loaded.setdefault("decks", [])
        loaded.setdefault("cards", [])
        loaded.setdefault("ratings", [])
        loaded.setdefault("processes", [])

        yield loaded

        changed = loaded
        db[DB_KEY] = bytes(json.dumps(changed), "utf-8")
