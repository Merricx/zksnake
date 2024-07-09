from ..symbolic import Symbol, SymbolArray
from ..r1cs import ConstraintTemplate


def nbits(a):
    n = 1
    r = 0
    while n - 1 < a:
        r += 1
        n *= 2

    return r


class BinSum(ConstraintTemplate):
    def __init__(self, n, ops):
        super().__init__()
        self.n = n
        self.ops = ops

    def main(self, *args):

        nout = nbits((2**self.n - 1) * self.ops)

        inp = args[0]
        out = args[1]

        assert len(inp) == self.ops and len(inp[0]) == self.n
        assert isinstance(out, (SymbolArray, list)) and len(out) == nout

        aux = Symbol("aux")

        lin = 0
        lout = 0

        lin = 0
        e2 = 1
        for k in range(self.n):
            for j in range(self.ops):
                lin += inp[j][k] * e2

            e2 *= 2

        e2 = 1
        for k in range(nout):
            self.add_hint(lambda x, i: (x >> i) & 1, out[k], args=(aux, k))
            self.add_constraint(0 == (1 - out[k]) * out[k])

            lout += out[k] * e2
            e2 *= 2

        self.add_constraint(aux == lin)
        self.add_constraint(lout == lin)
