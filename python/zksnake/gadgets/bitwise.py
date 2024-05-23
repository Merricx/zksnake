from ..symbolic import SymbolArray
from ..r1cs import ConstraintTemplate
from .bitify import NumToBits, BitsToNum


class AndGate(ConstraintTemplate):
    def main(self, *args):
        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        self.add_constraint(out == inp1 * inp2)


class OrGate(ConstraintTemplate):
    def main(self, *args):
        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        self.add_constraint(inp1 + inp2 - out == inp1 * inp2)


class XorGate(ConstraintTemplate):
    def main(self, *args):
        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        self.add_constraint(inp1 + inp2 - out == 2 * inp1 * inp2)


class NotGate(ConstraintTemplate):
    def main(self, *args):
        inp = args[0]
        out = args[1]

        self.add_constraint(out == 1 - inp)


class NandGate(ConstraintTemplate):
    def main(self, *args):
        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        self.add_constraint(1 - out == inp1 * inp2)


class NorGate(ConstraintTemplate):
    def main(self, *args):
        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        self.add_constraint(inp1 + inp2 + out - 1 == inp1 * inp2)


class And(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.n_bit = n

    def main(self, *args):

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        inp1_bit = SymbolArray("inp1_bit", self.n_bit)
        inp2_bit = SymbolArray("inp2_bit", self.n_bit)
        out_bit = SymbolArray("out_bit", self.n_bit)

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(inp1_bit == n2b("n2b_inp1", inp1))
        self.add_template(inp2_bit == n2b("n2b_inp2", inp2))

        and_gate = AndGate()
        for i in range(self.n_bit):
            self.add_template(
                out_bit[i] == and_gate("and_gate", inp1_bit[i], inp2_bit[i])
            )

        self.add_template(out == b2n("b2n", out_bit))


class Or(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.n_bit = n

    def main(self, *args):

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        inp1_bit = SymbolArray("inp1_bit", self.n_bit)
        inp2_bit = SymbolArray("inp2_bit", self.n_bit)
        out_bit = SymbolArray("out_bit", self.n_bit)

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(inp1_bit == n2b("n2b_inp1", inp1))
        self.add_template(inp2_bit == n2b("n2b_inp2", inp2))

        or_gate = OrGate()
        for i in range(self.n_bit):
            self.add_template(
                out_bit[i] == or_gate("or_gate", inp1_bit[i], inp2_bit[i])
            )

        self.add_template(out == b2n("b2n", out_bit))


class Xor(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.n_bit = n

    def main(self, *args):

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        inp1_bit = SymbolArray("inp1_bit", self.n_bit)
        inp2_bit = SymbolArray("inp2_bit", self.n_bit)
        out_bit = SymbolArray("out_bit", self.n_bit)

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(inp1_bit == n2b("n2b_inp1", inp1))
        self.add_template(inp2_bit == n2b("n2b_inp2", inp2))

        xor_gate = XorGate()
        for i in range(self.n_bit):
            self.add_template(
                out_bit[i] == xor_gate("xor_gate", inp1_bit[i], inp2_bit[i])
            )

        self.add_template(out == b2n("b2n", out_bit))


class Not(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.n_bit = n

    def main(self, *args):

        inp = args[0]
        out = args[1]

        inp_bit = SymbolArray("inp_bit", self.n_bit)
        out_bit = SymbolArray("out_bit", self.n_bit)

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(inp_bit == n2b("n2b_inp", inp))

        not_gate = NotGate()
        for i in range(self.n_bit):
            self.add_template(out_bit[i] == not_gate("not_gate", inp_bit[i]))

        self.add_template(out == b2n("b2n", out_bit))


class Nand(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.n_bit = n

    def main(self, *args):

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        inp1_bit = SymbolArray("inp1_bit", self.n_bit)
        inp2_bit = SymbolArray("inp2_bit", self.n_bit)
        out_bit = SymbolArray("out_bit", self.n_bit)

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(inp1_bit == n2b("n2b_inp1", inp1))
        self.add_template(inp2_bit == n2b("n2b_inp2", inp2))

        nand_gate = NandGate()
        for i in range(self.n_bit):
            self.add_template(
                out_bit[i] == nand_gate("nand_gate", inp1_bit[i], inp2_bit[i])
            )

        self.add_template(out == b2n("b2n", out_bit))


class Nor(ConstraintTemplate):
    def __init__(self, n=256):
        super().__init__()
        self.n_bit = n

    def main(self, *args):

        inp1 = args[0]
        inp2 = args[1]
        out = args[2]

        inp1_bit = SymbolArray("inp1_bit", self.n_bit)
        inp2_bit = SymbolArray("inp2_bit", self.n_bit)
        out_bit = SymbolArray("out_bit", self.n_bit)

        n2b = NumToBits(self.n_bit)
        b2n = BitsToNum(self.n_bit)

        self.add_template(inp1_bit == n2b("n2b_inp1", inp1))
        self.add_template(inp2_bit == n2b("n2b_inp2", inp2))

        nor_gate = NorGate()
        for i in range(self.n_bit):
            self.add_template(
                out_bit[i] == nor_gate("nor_gate", inp1_bit[i], inp2_bit[i])
            )

        self.add_template(out == b2n("b2n", out_bit))
