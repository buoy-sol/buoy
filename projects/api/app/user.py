from dataclasses import dataclass, field

from solders.pubkey import Pubkey


@dataclass
class User:

    # identity
    address: Pubkey

    # the Studycard the user is currently holding
    holding: str | None

    @classmethod
    def create(cls):
        return cls()

    def get_skill(
        self, rates_by_user: list[dict], rates_by_others: list[dict]
    ) -> float:

        by_user = {}
        by_others = {}

        for rate in rates_by_user:
            by_user.setdefault(rate[":rating/for"], [])
            by_user[rate[":rating/for"]].append(int(rate[":rating/value"]))

        for rate in rates_by_others:
            by_others.setdefault(rate[":rating/for"], [])
            by_others[rate[":rating/for"]].append(int(rate[":rating/value"]))

        for k, rates in by_user.items():
            by_user[k] = sum(rates) / len(rates)

        for k, rates in by_others.items():
            by_others[k] = sum(rates) / len(rates)

        adjusted = []

        for k, avg in by_others.items():
            if k not in by_user:
                continue

            if by_user[k] == avg:
                adjusted.append(by_user[k])
                continue

            if by_user[k] < avg:
                diff = avg - by_user[k]
                adjusted.append(by_user[k] + (diff / 2))
                continue

            if by_user[k] > avg:
                diff = by_user[k] - avg
                adjusted.append(by_user[k] - (diff / 2))
                continue

        if not any(adjusted):
            return 0

        return sum(adjusted) / len(adjusted)
