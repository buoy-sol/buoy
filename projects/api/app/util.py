import hashlib
import typing

SESS_KEY = "solana:session"


ErrorResult = typing.NewType("ErrorResult", str)


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
    def resolve_session_from_cookies(
        cookies: dict, mem: object
    ) -> typing.Tuple[dict | None, ErrorResult]:
        if SESS_KEY not in cookies:
            return None, "Missing credentials in request"

        handle = cookies.get(SESS_KEY)
        retrieved = mem.session.get(handle, None)
        if retrieved is None:
            return None, "Unathorized"

        return retrieved, None

    @staticmethod
    def resolve_address_from_cookies(
        cookies: dict, mem: object
    ) -> typing.Tuple[str | None, ErrorResult]:
        retrieved, err = F.resolve_session_from_cookies(cookies, mem)

        if err is not None:
            return None, err

        if "address" not in retrieved:
            return None, "Corrupted session data"

        return retrieved["address"], None

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
