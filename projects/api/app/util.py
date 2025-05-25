import hashlib
import operator
import typing

from os.path import join

SESS_KEY = "solana:session"

ErrorResult = typing.NewType("ErrorResult", str)

T = typing.TypeVar("T")


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
                if isinstance(v, typing.Callable):
                    matched = v(e.get(k))

                if not matched:
                    ok = False

            return ok

        return inner

    @staticmethod
    def intersection(a: list[T], b: list[T]) -> list[T]:
        return list(set(a).intersection(set(b)))

    @staticmethod
    def where_eav(form: list[T]) -> list[list[T]]:
        xe, xa, xv = form

        def inner(el: list[T]) -> bool:
            e, a, v, t, added = el
            for left, right in [(xe, e), (xa, a), (xv, v)]:
                if "?" == left:
                    continue

                ok = left == right
                if isinstance(left, typing.Callable):
                    ok = left(right)

            return ok

        return inner

    @staticmethod
    def load_entity(dataset: list[list[typing.Any]]) -> typing.Callable:

        def inner(el: str) -> dict[str, typing.Any]:
            entity: dict = {}
            for fact in dataset:
                e, a, v, t, added = fact
                if el == e:
                    entity[a] = v if added else None

            entity[":system/entity-id"] = el
            entity[":system/entity-timestamp"] = t
            # entity[":system/entity-added"] = added

            return entity

        return inner

    @staticmethod
    def resolve_session_from_cookies(
        cookies: dict, mem: object
    ) -> typing.Tuple[dict | None, ErrorResult]:
        if SESS_KEY not in cookies:
            return None, ErrorResult("Missing credentials in request")

        handle = cookies.get(SESS_KEY)
        retrieved = mem.session.get(handle, None)
        if retrieved is None:
            return None, ErrorResult("Unathorized")

        return retrieved, None

    @staticmethod
    def resolve_address_from_cookies(
        cookies: dict,
    ) -> typing.Tuple[dict | None, ErrorResult | None]:
        session, err = F.resolve_session_from_cookies(cookies)

        if err is not None:
            return None, err

        if "address" not in session:
            return None, ErrorResult("Corrupted session!")

        return session.get("address"), None

    @staticmethod
    def resolve_token_from_headers(
        headers: dict,
    ) -> typing.Tuple[str | None, ErrorResult | None]:
        parts = headers.get("Authorization", "").split("Bearer ")

        if 2 > len(parts):
            return None, "Missing credentials"

        _, token = parts

        return token, None

    @staticmethod
    def resolve_session_from_bearer(
        headers: dict, mem: object
    ) -> typing.Tuple[str | None, ErrorResult]:
        token, err = F.resolve_token_from_headers(headers)

        if err is not None:
            return None, err

        retrieved = mem.session.get(token, None)
        if retrieved is None:
            return None, ErrorResult("Unathorized!")

        return retrieved, None

    @staticmethod
    def resolve_address_from_bearer(
        headers: dict,
        mem: object,
    ) -> typing.Tuple[str | None, ErrorResult | None]:
        session, err = F.resolve_session_from_bearer(headers, mem)

        if err is not None:
            return None, err

        if "address" not in session:
            return None, ErrorResult("Corrupted session!")

        return session.get("address"), None

    @staticmethod
    def resolve_reviews_path(dbpath: str, address: str) -> str:
        return dbpath + f".reviews.{address}"

    @staticmethod
    def resolve_events_path(dbpath: str) -> str:
        return dbpath + f".events"

    @staticmethod
    def get_card_rent_account():
        return None

    @staticmethod
    def md5sum(filename: str) -> str:
        result = hashlib.md5()

        with open(filename, "rb") as f:
            chunk = f.read(8192)
            while chunk:
                result.update(chunk)
                chunk = f.read(8192)

        return result.hexdigest()

    @staticmethod
    def counted(vals: list[str]) -> int:
        return sum(map(operator.floordiv, vals, vals))
