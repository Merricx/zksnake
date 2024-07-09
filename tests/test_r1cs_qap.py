import pytest

from zksnake.symbolic import Symbol, SymbolArray
from zksnake.r1cs import ConstraintSystem, ConstraintTemplate


def test_basic_r1cs_bn254():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")

    cs = ConstraintSystem(["x"], ["y"])
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    pub, priv = cs.solve({"x": 3}, {"y": 35})

    qap = cs.compile()

    qap.evaluate_witness(pub + priv)


def test_basic_r1cs_bls12_381():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")

    cs = ConstraintSystem(["x"], ["y"], "BLS12_381")
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    qap = cs.compile()

    pub, priv = cs.solve({"x": 3}, {"y": 35})

    qap.evaluate_witness(pub + priv)


def test_constraint_structure():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")
    v2 = Symbol("v2")
    v3 = Symbol("v3")
    v4 = Symbol("v4")

    cs = ConstraintSystem(["x"], ["y"])
    cs.add_constraint(v3 == v1 + v2)  # unordered constraint with more than 1 unknowns
    cs.add_constraint(0 == (1 + v1) * (3 + x))  # assignment in rhs
    cs.add_constraint(x + v2 == v1)  # multiple var in lhs
    cs.add_constraint(
        1 * v1 + 1 * v2 == (1 + 168696 * v3) * v4
    )  # unknown var in a*b form
    cs.add_constraint(y == v1 + v2 + v3 + v4)

    cs.set_public(y)

    qap = cs.compile()

    pub, priv = cs.solve({"x": 3})

    qap.evaluate_witness(pub + priv)


def test_r1cs_loop_constraint():

    n_power = 64
    v = []
    inp = Symbol("inp")
    out = Symbol("out")
    for i in range(n_power - 1):
        v.append(Symbol(f"v{i}"))

    cs = ConstraintSystem([inp], ["out"])

    cs.add_constraint(v[0] == inp * inp)
    for i in range(1, n_power - 1):
        cs.add_constraint(v[i] == v[i - 1] * inp)

    cs.add_constraint(out == v[n_power - 2])
    cs.set_public(out)

    qap = cs.compile()

    pub, priv = cs.solve({"inp": 2}, {"out": 2**n_power})

    qap.evaluate_witness(pub + priv)


def test_constraint_template():

    class Power(ConstraintTemplate):
        def __init__(self, n):
            super().__init__()
            self.n_power = n

        def main(self, *args):
            n_power = self.n_power

            v = SymbolArray("v", n_power - 1)

            inp = args[0]
            out = args[1]
            self.add_constraint(v[0] == inp * inp)
            for i in range(1, n_power - 1):
                self.add_constraint(v[i] == v[i - 1] * inp)

            self.add_constraint(out == v[n_power - 2])

    i = Symbol("i")
    v1 = Symbol("v1")
    v2 = Symbol("v2")
    out = Symbol("out")
    power3 = Power(3)
    power5 = Power(5)
    power8 = Power(8)

    cs1 = ConstraintSystem([i], [out])
    cs2 = ConstraintSystem([i], [out])
    cs3 = ConstraintSystem([i], [out])

    cs3.add_constraint(v1 == i + 1)
    cs3.add_constraint(out == v2 * 2)

    cs1.add_template(out == power5("pow5", i))
    cs2.add_template(out == power8("pow8", i))
    cs3.add_template(v2 == power3("pow3", v1))

    assert cs1.evaluate({"i": 2}, {"out": 2**5})
    assert cs2.evaluate({"i": 2}, {"out": 2**8})
    assert cs3.evaluate({"i": 3}, {"out": ((3 + 1) ** 3) * 2})


def test_constraint_hint():

    x = Symbol("x")
    out = Symbol("out")
    n_bit = 32

    bits = []
    for i in range(n_bit):
        bits.append(Symbol(f"b{i}"))

    cs = ConstraintSystem([x], [out])
    for i in range(n_bit):
        cs.add_constraint(0 == (1 - bits[i]) * bits[i])

    eq = x
    for i in range(n_bit):
        eq -= (2**i) * bits[i]

    cs.add_constraint(0 == eq)

    for i, b in enumerate(bits):
        f = lambda x, i: (x >> i) & 1
        cs.add_hint(f, b, (x, i))

    cs.evaluate({"x": 13337})

    expected_bits = bin(13337)[2:].zfill(n_bit)[::-1]
    for i in range(n_bit):
        assert cs.vars[f"b{i}"] == int(expected_bits[i])


def test_constraint_template_with_hint():

    class Num2Bits(ConstraintTemplate):
        def __init__(self, n):
            super().__init__()
            self.n_bit = n

        def main(self, *args):
            n_bit = self.n_bit

            inp = args[0]
            v = args[1]

            for i in range(n_bit):
                self.add_constraint(0 == (1 - v[i]) * v[i])

            eq = inp
            for i in range(n_bit):
                eq -= (2**i) * v[i]

            self.add_constraint(0 == eq)

            for i, b in enumerate(v):
                f = lambda x, i: (x >> i) & 1
                self.add_hint(f, b, (inp, i))

    n_bit = 256
    inp = Symbol("i")
    bits = []
    out = SymbolArray("bit", n_bit)

    num2bits = Num2Bits(n_bit)

    cs = ConstraintSystem([inp], bits)

    cs.add_template(out == num2bits("n2b", inp))

    cs.evaluate({"i": 13333333337})

    expected_bits = bin(13333333337)[2:].zfill(n_bit)[::-1]
    for i in range(n_bit):
        assert cs.vars[f"bit[{i}]"] == int(expected_bits[i])
