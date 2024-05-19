from ..symbolic import Symbol
from ..r1cs import ConstraintTemplate

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
        self.inputs = ["inp"]
        self.outputs = ["out"]
        self.modulus = modulus

    def main(self):
        modulus = self.modulus

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

    def __init__(self, modulus):
        super().__init__()
        self.inputs = ["inp"]
        self.outputs = ["out"]
        self.modulus = modulus

    def main(self):
        modulus = self.modulus

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")

        sub = Symbol("sub")
        out = Symbol("out")

        isz = IsZero(modulus)

        self.add_hint(lambda a, b: a - b, sub, args=(inp1, inp2))
        self.add_constraint(sub == inp1 - inp2)
        self.add_template(isz("is_zero", {"inp": sub}, {"out": out}))


class LessThan(ConstraintTemplate):
    """
    Check if `inp1` < `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `n` as number of bits
    """

    def __init__(self, n):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):
        n = self.n_bit

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        bitify_inp = Symbol("bit_inp")
        n2b_out = [Symbol(f"bit{i}") for i in range(n + 1)]
        n2b = NumToBits(n + 1)

        out_dict = {}
        for i in range(n + 1):
            out_dict[f"bit{i}"] = n2b_out[i]

        self.add_template(n2b("n2b", {"inp": bitify_inp}, out_dict))

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
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):
        n = self.n_bit

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        inp2_add_1 = Symbol("inp2_add_1")
        out = Symbol("out")

        lt = LessThan(n)
        self.add_constraint(inp2_add_1 == inp2 + 1)
        self.add_template(lt("lt", {"inp1": inp1, "inp2": inp2_add_1}, {"out": out}))


class GreaterThan(ConstraintTemplate):
    """
    Check if `inp1` > `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, n):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):
        n = self.n_bit

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        lt = LessThan(n)
        self.add_template(lt("lt", {"inp1": inp2, "inp2": inp1}, {"out": out}))


class GreaterEqThan(ConstraintTemplate):
    """
    Check if `inp1` >= `inp2`

    inputs: `[inp1, inp2]`
    outputs: `[out]`
    args: `p` as field modulus
    """

    def __init__(self, n):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):
        n = self.n_bit

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        inp1_add_1 = Symbol("inp1_add_1")
        out = Symbol("out")

        lt = LessThan(n)
        self.add_constraint(inp1_add_1 == inp1 + 1)
        self.add_template(lt("lt", {"inp1": inp2, "inp2": inp1_add_1}, {"out": out}))
