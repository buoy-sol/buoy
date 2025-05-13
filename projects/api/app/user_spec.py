import operator
import time

from mamba import context, describe, it
from expects import equal, expect

from app.db import dbm_open_bytes
from app.user import User
from app.rating import Rating
from app.util import F

DATABASE = "/opt/skills/dat/db"

with describe("user"):
    with context("skill level"):
        with it(
            "resolves a skill level by balancing user's difficulty ratings against others'"
        ):
            with dbm_open_bytes(DATABASE, "c") as db:
                _user = next(
                    filter(F.where({"address": "nil"}), db["users"].values()), None
                )

                assert _user is not None

                user = User(**_user)

                expected = 6.75

                sample_ratings = [
                    {
                        "card": "x1",
                        "value": 5.5,
                        "contributor": user.address,
                        "timestamp": int(time.time()),
                    },
                    {
                        "card": "x2",
                        "value": 4.5,
                        "contributor": user.address,
                        "timestamp": int(time.time()),
                    },
                    {
                        "card": "x1",
                        "value": 7.5,
                        "contributor": "user-A",
                        "timestamp": int(time.time()),
                    },
                    {
                        "card": "x1",
                        "value": 8.5,
                        "contributor": "user-B",
                        "timestamp": int(time.time()),
                    },
                ]

                ratings = list(
                    map(
                        Rating.from_dict,
                        filter(F.where({"contributor": user.address}), sample_ratings),
                    )
                )

                user_rated_cards = list(map(operator.attrgetter("card"), ratings))

                relevant = list(
                    filter(
                        lambda e: e.card in user_rated_cards
                        and e.contributor != user.address,
                        map(Rating.from_dict, sample_ratings),
                    )
                )

                actual = user.get_skill(ratings, relevant)
                expect(actual).to(equal(expected))
