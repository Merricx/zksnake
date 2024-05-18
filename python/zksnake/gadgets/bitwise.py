from ..symbolic import Symbol
from ..r1cs import ConstraintTemplate


class And(ConstraintTemplate):
    def main(self, *args, **kwds):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        self.add_constraint(out == inp1 * inp2)


class Or(ConstraintTemplate):
    def main(self, *args, **kwds):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        self.add_constraint(inp1 + inp2 - out == inp1 * inp2)


class Xor(ConstraintTemplate):
    def main(self, *args, **kwds):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        self.add_constraint(inp1 + inp2 - out == 2 * inp1 * inp2)


class Not(ConstraintTemplate):
    def main(self, *args, **kwds):

        inp = Symbol("inp")
        out = Symbol("out")

        self.add_constraint(1 + inp - out == 2 * inp)


class Nand(ConstraintTemplate):
    def main(self, *args, **kwds):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        self.add_constraint(1 - out == inp1 * inp2)


class Nor(ConstraintTemplate):
    def main(self, *args, **kwds):

        inp1 = Symbol("inp1")
        inp2 = Symbol("inp2")
        out = Symbol("out")

        self.add_constraint(out + inp1 + inp2 - 1 == inp1 * inp2)
