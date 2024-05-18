from ..symbolic import Symbol
from ..r1cs import ConstraintTemplate


class Bitify(ConstraintTemplate):
    """
    Convert number to n-bits binary

    inputs: `[inp]`
    outputs: `[bit[0], bit[1], bit[2], ..., bit[n-1]]`
    args: `n`
    """

    def __init__(self, n):
        super().__init__()
        self.inputs = ["inp"]
        self.outputs = [f"bit{i}" for i in range(n)]
        self.n_bit = n

    def main(self):
        n_bit = self.n_bit

        v = []
        for i in range(n_bit):
            v.append(Symbol(f"bit{i}"))

        inp = Symbol("inp")

        for i in range(n_bit):
            self.add_constraint(0 == (1 - v[i]) * v[i])

        eq = inp
        for i in range(n_bit):
            eq -= (2**i) * v[i]

        self.add_constraint(0 == eq)

        for i, b in enumerate(v):
            self.add_hint(lambda x, i: (x >> i) & 1, b, (inp, i))
