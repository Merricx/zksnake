import pytest

from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem, ConstraintTemplate
from zksnake.groth16 import Prover, Setup, Verifier


def test_basic_r1cs_bn128():

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


def test_unused_public_input():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")
    unused = Symbol("unused")

    cs = ConstraintSystem(["x", "unused"], ["y"])
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(unused)
    cs.set_public(y)

    pub, priv = cs.solve({"x": 3, "unused": 1337}, {"y": 35})

    qap = cs.compile()

    setup = Setup(qap)
    pkey, vkey = setup.generate()

    prover = Prover(qap, pkey)
    verifier = Verifier(vkey)

    proof = prover.prove(pub, priv)

    # try to forge proof from unused public input
    pub[2] = 1330000000
    assert verifier.verify(proof, pub) is False


def test_constraint_template():

    class Power(ConstraintTemplate):
        def main(self, *args, **kwds):
            n_power = args[0]

            v = []
            for i in range(n_power - 1):
                v.append(Symbol(f"v{i}"))

            inp = Symbol("inp")
            out = Symbol("out")
            self.add_constraint(v[0] == inp * inp)
            for i in range(1, n_power - 1):
                self.add_constraint(v[i] == v[i - 1] * inp)

            self.add_constraint(out == v[n_power - 2])
            self.set_public(out)

    i = Symbol("i")
    v1 = Symbol("v1")
    v2 = Symbol("v2")
    out = Symbol("out")
    power = Power(["inp"], ["out"])

    cs1 = ConstraintSystem([i], [out])
    cs2 = ConstraintSystem([i], [out])
    cs3 = ConstraintSystem([i], [out])

    cs3.add_constraint(v1 == i + 1)
    cs3.add_constraint(out == v2 * 2)

    cs1.add_template(power(5), {"inp": i}, {"out": out})
    cs3.add_template(power(3), {"inp": v1}, {"out": v2})
    cs2.add_template(power(8), {"inp": i}, {"out": out})

    assert cs1.evaluate({"i": 2}, {"out": 2**5})
    assert cs2.evaluate({"i": 2}, {"out": 2**8})
    assert cs3.evaluate({"i": 3}, {"out": 4**3 * 2})


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
