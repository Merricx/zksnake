from ..symbolic import Symbol
from ..r1cs import ConstraintTemplate

from .bitify import Bitify


class IsZero(ConstraintTemplate):
    """
    Check whether number is equal zero or not

    inputs: `[inp]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def main(self, *args, **kwds):
        modulus = args[0]

        inp = Symbol("inp")
        out = Symbol("out")

        inv = Symbol("inv")

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

    def main(self, *args, **kwds):
        modulus = args[0]

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")

        sub = Symbol("sub")
        out = Symbol("out")

        isz = IsZero(["inp"], ["out"])

        self.add_hint(lambda a, b: a - b, sub, args=(inp1, inp2))
        self.add_template(isz(modulus), {"inp": sub}, {"out": out})


class LessThan(ConstraintTemplate):
    """
    Check if `inp1` < `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `n` as number of bits
    """

    def main(self, *args, **kwds):
        n = args[0]

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        bitify_inp = Symbol("bit_inp")
        n2b_out = [Symbol(f"bit{i}") for i in range(n + 1)]
        n2b = Bitify(["inp"], n2b_out)

        out_dict = {}
        for i in range(n + 1):
            out_dict[f"bit{i}"] = n2b_out[i]

        self.add_template(n2b(n + 1), {"inp": bitify_inp}, out_dict)
        # TODO: if add_template triggered, automatically replace bitify_inp in all found constraints
        self.add_constraint(Symbol("Bitify.inp") == inp1 + (1 << n) - inp2)
        self.add_constraint(out == 1 - n2b_out[-1])


class LessEqThan(ConstraintTemplate):
    """
    Check if `inp1` <= `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def main(self, *args, **kwds):
        n = args[0]

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        inp2_add_1 = Symbol("inp2_add_1")
        out = Symbol("out")

        lt = LessThan([inp1, inp2], [out])
        self.add_constraint(inp2_add_1 == inp2 + 1)
        self.add_template(lt(n), {"inp1": inp1, "inp2": inp2_add_1}, {"out": out})


class GreaterThan(ConstraintTemplate):
    """
    Check if `inp1` > `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def main(self, *args, **kwds):
        n = args[0]

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        lt = LessThan([inp1, inp2], [out])
        self.add_template(lt(n), {"inp1": inp2, "inp2": inp1}, {"out": out})


class GreaterEqThan(ConstraintTemplate):
    """
    Check if `inp1` >= `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def main(self, *args, **kwds):
        n = args[0]

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        inp1_add_1 = Symbol("inp1_add_1")
        out = Symbol("out")

        lt = LessThan([inp1, inp2], [out])
        self.add_constraint(inp1_add_1 == inp1 + 1)
        self.add_template(lt(n), {"inp1": inp2, "inp2": inp1_add_1}, {"out": out})
