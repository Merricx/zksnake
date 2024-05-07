import pytest

from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem


def test_basic_r1cs_bn128():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")

    cs = ConstraintSystem(["x"], "y")
    cs.add(v1 == x * x)
    cs.add(y - 5 - x == v1 * x)
    cs.set_public(y)

    pub, priv = cs.solve({"x": 3}, 35)

    qap = cs.compile()

    qap.evaluate_witness(pub + priv)


def test_basic_r1cs_bls12_381():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")

    cs = ConstraintSystem(["x"], "y", "BLS12_381")
    cs.add(v1 == x * x)
    cs.add(y - 5 - x == v1 * x)
    cs.set_public(y)

    qap = cs.compile()

    pub, priv = cs.solve({"x": 3}, 35)

    qap.evaluate_witness(pub + priv)


def test_r1cs_big_constraint():

    n_power = 64
    v = []
    inp = Symbol("inp")
    out = Symbol("out")
    for i in range(n_power - 1):
        v.append(Symbol(f"v{i}"))

    cs = ConstraintSystem([inp], "out")

    cs.add(v[0] == inp * inp)
    for i in range(1, n_power - 1):
        cs.add(v[i] == v[i - 1] * inp)

    cs.add(out == v[n_power - 2])
    cs.set_public(out)

    qap = cs.compile()

    pub, priv = cs.solve({"inp": 2}, 2**n_power)

    qap.evaluate_witness(pub + priv)


def test_unused_public_input():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")
    unused = Symbol("unused")

    cs = ConstraintSystem(["x", "unused"], "y")
    cs.add(v1 == x * x)
    cs.add(y - 5 - x == v1 * x)
    cs.set_public(unused)
    cs.set_public(y)

    pub, priv = cs.solve({"x": 3, "unused": 1337}, 35)

    qap = cs.compile()

    qap.evaluate_witness(pub + priv)
