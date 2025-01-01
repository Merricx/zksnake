import pytest

from zksnake.arithmetization.r1cs import R1CS
from zksnake.constant import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD
from zksnake.groth16.qap import QAP
from zksnake.arithmetization import ConstraintSystem, Var


def test_basic_r1cs_bn254():

    x = Var("x")
    y = Var("y")
    v1 = Var("v1")

    cs = ConstraintSystem(["x"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    r1cs = R1CS(cs)
    r1cs.compile()

    pub, priv = r1cs.generate_witness(cs.solve({"x": 3}))

    qap = QAP()
    qap.from_r1cs(r1cs)

    qap.evaluate_witness(pub + priv)


def test_basic_r1cs_bls12_381():

    x = Var("x")
    y = Var("y")
    v1 = Var("v1")

    cs = ConstraintSystem(["x"], ["y"], BLS12_381_SCALAR_FIELD)
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    r1cs = R1CS(cs, "BLS12_381")
    r1cs.compile()

    pub, priv = r1cs.generate_witness(cs.solve({"x": 3}))

    qap = QAP()
    qap.from_r1cs(r1cs)

    qap.evaluate_witness(pub + priv)


def test_constraint_structure():

    x = Var("x")
    y = Var("y")
    v1 = Var("v1")
    v2 = Var("v2")
    v3 = Var("v3")
    v4 = Var("v4")

    cs = ConstraintSystem(["x"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(v1 == x*x)
    cs.add_constraint(v2 == v1 + x)
    cs.add_constraint(v1 + v2 == v3)
    cs.add_constraint(v4 == (v1 + v2) / (168696*v3 + 1))
    cs.add_constraint(v1 + v2 + v3 + v4 == y)

    cs.set_public(y)

    r1cs = R1CS(cs)
    r1cs.compile()

    s = cs.solve({"x": 3})
    pub, priv = r1cs.generate_witness(s)

    qap = QAP()
    qap.from_r1cs(r1cs)

    qap.evaluate_witness(pub + priv)


def test_r1cs_loop_constraint():

    n_power = 64
    v = []
    inp = Var("inp")
    out = Var("out")
    for i in range(n_power - 1):
        v.append(Var(f"v{i}"))

    cs = ConstraintSystem(["inp"], ["out"], BN254_SCALAR_FIELD)

    cs.add_constraint(v[0] == inp * inp)
    for i in range(1, n_power - 1):
        cs.add_constraint(v[i] == v[i - 1] * inp)

    cs.add_constraint(out == v[n_power - 2])
    cs.set_public(out)

    r1cs = R1CS(cs)
    r1cs.compile()

    pub, priv = r1cs.generate_witness(cs.solve({"inp": 2}))

    qap = QAP()
    qap.from_r1cs(r1cs)

    qap.evaluate_witness(pub + priv)