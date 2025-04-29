"""?
"""

from mamba import context, describe, it  # type: ignore[import-untyped]
from expects import expect, equal  # type: ignore[import-untyped]

from app.chain.rpc import rpc  # pylint: disable=import-error

with describe("rpc handler "):
    with context("???"):
        with it("can create a token mint") as self:

            rpc.get_mint_account()
            self.expected = 0

            self.actual = 1
            expect(self.actual).to(equal(self.expected))
