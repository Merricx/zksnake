from ..symbolic import Symbol, SymbolArray
from ..arithmetization.constraints import ConstraintTemplate

from .bitify import NumToBits


class IsZero(ConstraintTemplate):
    """
    Check whether number is equal zero or not

    inputs: `[inp]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, modulus):
        super().__init__()
        self.modulus = modulus

    def main(self, *args):
        modulus = self.modulus

        inp = args[0]
        out = args[1]

        inv = Symbol("inv")

        assert isinstance(inp, Symbol) and isinstance(out, Symbol)

        self.add_constraint(1 - out == inp * inv)
        self.add_constraint(0 == inp * out)
        self.add_hint(
            lambda x, p: x if x == 0 else pow(x, -1, p), inv, args=(inp, modulus)
        )


class IsEqual(ConstraintTemplate):
    """
    Check whether `inp1` and `inp2` is equal

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, modulus):
        super().__init__()
        self.modulus = modulus

    def main(self, *args):
        modulus = self.modulus

        inp1 = args[0]
        inp2 = args[1]

        out = args[2]
        sub = Symbol("sub")

        assert (
            isinstance(inp1, Symbol)
            and isinstance(inp2, Symbol)
            and isinstance(out, Symbol)
        )

        isz = IsZero(modulus)

        self.add_hint(lambda a, b: a - b, sub, args=(inp1, inp2))
        self.add_constraint(sub == inp1 - inp2)
        self.add_template(out == isz("is_zero", sub))


class LessThan(ConstraintTemplate):
    """
    Check if `inp1` < `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `n` as number of bits
    """

    def __init__(self, n):
        super().__init__()
        self.n_bit = n

    def main(self, *args):
        n = self.n_bit

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        bitify_inp = Symbol("bit_inp")
        n2b_out = SymbolArray("bit", n + 1)
        n2b = NumToBits(n + 1)

        self.add_template(n2b_out == n2b("n2b", bitify_inp))
        self.add_constraint(bitify_inp == inp1 + (1 << n) - inp2)
        self.add_constraint(out == 1 - n2b_out[-1])


class LessEqThan(ConstraintTemplate):
    """
    Check if `inp1` <= `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, n):
        super().__init__()
        self.n_bit = n

    def main(self, *args):
        n = self.n_bit

        inp1 = args[0]
        inp2 = args[1]
        inp2_add_1 = Symbol("inp2_add_1")
        out = args[2]

        lt = LessThan(n)
        self.add_constraint(inp2_add_1 == inp2 + 1)
        self.add_template(out == lt("lt", inp1, inp2_add_1))


class GreaterThan(ConstraintTemplate):
    """
    Check if `inp1` > `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, n):
        super().__init__()
        self.n_bit = n

    def main(self, *args):
        n = self.n_bit

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        lt = LessThan(n)
        self.add_template(out == lt("lt", inp2, inp1))


class GreaterEqThan(ConstraintTemplate):
    """
    Check if `inp1` >= `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, n):
        super().__init__()
        self.n_bit = n

    def main(self, *args):
        n = self.n_bit

        inp1 = args[0]
        inp2 = args[1]
        inp1_add_1 = Symbol("inp1_add_1")
        out = args[2]

        lt = LessThan(n)
        self.add_constraint(inp1_add_1 == inp1 + 1)
        self.add_template(out == lt("lt", inp2, inp1_add_1))
