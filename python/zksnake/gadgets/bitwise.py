from ..symbolic import Symbol
from ..r1cs import ConstraintTemplate
from .bitify import NumToBits, BitsToNum


class And(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        inp1_bit = [Symbol(f"inp1_bit{i}") for i in range(self.n_bit)]
        inp2_bit = [Symbol(f"inp2_bit{i}") for i in range(self.n_bit)]
        out_bit = [Symbol(f"out_bit{i}") for i in range(self.n_bit)]

        out_inp1_dict = {}
        out_inp2_dict = {}
        for i in range(self.n_bit):
            out_inp1_dict[f"bit{i}"] = inp1_bit[i]
            out_inp2_dict[f"bit{i}"] = inp2_bit[i]

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(n2b("n2b_inp1", {"inp": inp1}, out_inp1_dict))
        self.add_template(n2b("n2b_inp2", {"inp": inp2}, out_inp2_dict))

        out_dict = {}
        for i in range(self.n_bit):
            self.add_constraint(out_bit[i] == inp1_bit[i] * inp2_bit[i])
            out_dict[f"bit{i}"] = out_bit[i]

        self.add_template(b2n("b2n", out_dict, {"out": out}))


class Or(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        inp1_bit = [Symbol(f"inp1_bit{i}") for i in range(self.n_bit)]
        inp2_bit = [Symbol(f"inp2_bit{i}") for i in range(self.n_bit)]
        out_bit = [Symbol(f"out_bit{i}") for i in range(self.n_bit)]

        out_inp1_dict = {}
        out_inp2_dict = {}
        for i in range(self.n_bit):
            out_inp1_dict[f"bit{i}"] = inp1_bit[i]
            out_inp2_dict[f"bit{i}"] = inp2_bit[i]

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(n2b("n2b_inp1", {"inp": inp1}, out_inp1_dict))
        self.add_template(n2b("n2b_inp2", {"inp": inp2}, out_inp2_dict))

        out_dict = {}
        for i in range(self.n_bit):
            self.add_constraint(
                inp1_bit[i] + inp2_bit[i] - out_bit[i] == inp1_bit[i] * inp2_bit[i]
            )
            out_dict[f"bit{i}"] = out_bit[i]

        self.add_template(b2n("b2n", out_dict, {"out": out}))


class Xor(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        inp1_bit = [Symbol(f"inp1_bit{i}") for i in range(self.n_bit)]
        inp2_bit = [Symbol(f"inp2_bit{i}") for i in range(self.n_bit)]
        out_bit = [Symbol(f"out_bit{i}") for i in range(self.n_bit)]

        out_inp1_dict = {}
        out_inp2_dict = {}
        for i in range(self.n_bit):
            out_inp1_dict[f"bit{i}"] = inp1_bit[i]
            out_inp2_dict[f"bit{i}"] = inp2_bit[i]

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(n2b("n2b_inp1", {"inp": inp1}, out_inp1_dict))
        self.add_template(n2b("n2b_inp2", {"inp": inp2}, out_inp2_dict))

        out_dict = {}
        for i in range(self.n_bit):
            self.add_constraint(
                inp1_bit[i] + inp2_bit[i] - out_bit[i] == 2 * inp1_bit[i] * inp2_bit[i]
            )
            out_dict[f"bit{i}"] = out_bit[i]

        self.add_template(b2n("b2n", out_dict, {"out": out}))


class Not(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.inputs = ["inp"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):

        inp = Symbol("inp")
        out = Symbol("out")

        inp_bit = [Symbol(f"inp_bit{i}") for i in range(self.n_bit)]
        out_bit = [Symbol(f"out_bit{i}") for i in range(self.n_bit)]

        out_inp1_dict = {}
        for i in range(self.n_bit):
            out_inp1_dict[f"bit{i}"] = inp_bit[i]

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(n2b("n2b", {"inp": inp}, out_inp1_dict))

        out_dict = {}
        for i in range(self.n_bit):
            self.add_constraint(1 + inp_bit[i] - out_bit[i] == 2 * inp_bit[i])
            out_dict[f"bit{i}"] = out_bit[i]

        self.add_template(b2n("b2n", out_dict, {"out": out}))


class Nand(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        inp1_bit = [Symbol(f"inp1_bit{i}") for i in range(self.n_bit)]
        inp2_bit = [Symbol(f"inp2_bit{i}") for i in range(self.n_bit)]
        out_bit = [Symbol(f"out_bit{i}") for i in range(self.n_bit)]

        out_inp1_dict = {}
        out_inp2_dict = {}
        for i in range(self.n_bit):
            out_inp1_dict[f"bit{i}"] = inp1_bit[i]
            out_inp2_dict[f"bit{i}"] = inp2_bit[i]

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(n2b("n2b_inp1", {"inp": inp1}, out_inp1_dict))
        self.add_template(n2b("n2b_inp2", {"inp": inp2}, out_inp2_dict))

        out_dict = {}
        for i in range(self.n_bit):
            self.add_constraint(1 - out_bit[i] == inp1_bit[i] * inp2_bit[i])
            out_dict[f"bit{i}"] = out_bit[i]

        self.add_template(b2n("b2n", out_dict, {"out": out}))


class Nor(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.inputs = ["inp1", "inp2"]
        self.outputs = ["out"]
        self.n_bit = n

    def main(self):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        inp1_bit = [Symbol(f"inp1_bit{i}") for i in range(self.n_bit)]
        inp2_bit = [Symbol(f"inp2_bit{i}") for i in range(self.n_bit)]
        out_bit = [Symbol(f"out_bit{i}") for i in range(self.n_bit)]

        out_inp1_dict = {}
        out_inp2_dict = {}
        for i in range(self.n_bit):
            out_inp1_dict[f"bit{i}"] = inp1_bit[i]
            out_inp2_dict[f"bit{i}"] = inp2_bit[i]

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(n2b("n2b_inp1", {"inp": inp1}, out_inp1_dict))
        self.add_template(n2b("n2b_inp2", {"inp": inp2}, out_inp2_dict))

        out_dict = {}
        for i in range(self.n_bit):
            self.add_constraint(
                out_bit[i] + inp1_bit[i] + inp2_bit[i] - 1 == inp1_bit[i] * inp2_bit[i]
            )
            out_dict[f"bit{i}"] = out_bit[i]

        self.add_template(b2n("b2n", out_dict, {"out": out}))
