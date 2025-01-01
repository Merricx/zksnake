import pytest

from zksnake.arithmetization.plonkish import Plonkish
from zksnake.constant import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD
from zksnake.arithmetization import Var, ConstraintSystem
from zksnake.plonk import Prover, Proof, ProvingKey, Setup, Verifier, VerifyingKey


@pytest.fixture
def plonkish_data_bn254():

    x = Var("x")
    y = Var("y")
    v0 = Var('v0')
    v1 = Var('v1')
    v2 = Var('v2')
    v3 = Var('v3')
    v4 = Var('v4')
    v5 = Var('v5')
    v6 = Var('v6')

    cs = ConstraintSystem(["x"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(v0==x*x)
    cs.add_constraint(v1==x*x)
    cs.add_constraint(v2 == v1 * x)
    cs.add_constraint(v3 == v0 * 2 * 3)
    cs.add_constraint(v4 == 2*v1 * v2*3)
    cs.add_constraint(v5 == 2*v3 - v4)
    cs.add_constraint(v6 == 2 + v5 + 3)
    cs.add_constraint(y == v6 + v4 + 1337)
    cs.set_public(y)

    plonkish = Plonkish(cs)
    plonkish.compile()
    pub, priv = plonkish.generate_witness(cs.solve({"x": 3}))

    return plonkish, (pub, priv)

@pytest.fixture
def plonkish_data_bls12_381():

    x = Var("x")
    y = Var("y")
    v0 = Var('v0')
    v1 = Var('v1')
    v2 = Var('v2')
    v3 = Var('v3')
    v4 = Var('v4')
    v5 = Var('v5')
    v6 = Var('v6')

    cs = ConstraintSystem(["x"], ["y"], BLS12_381_SCALAR_FIELD)
    cs.add_constraint(v0==x*x)
    cs.add_constraint(v1==x*x)
    cs.add_constraint(v2 == v1 * x)
    cs.add_constraint(v3 == v0 * 2 * 3)
    cs.add_constraint(v4 == 2*v1 * v2*3)
    cs.add_constraint(v5 == 2*v3 - v4)
    cs.add_constraint(v6 == 2 + v5 + 3)
    cs.add_constraint(y == v6 + v4 + 1337)
    cs.set_public(y)

    plonkish = Plonkish(cs, "BLS12_381")
    plonkish.compile()

    pub, priv = plonkish.generate_witness(cs.solve({"x": 3}))

    return plonkish, (pub, priv)

def test_plonk_bn254(plonkish_data_bn254):

    plonkish, witness = plonkish_data_bn254
    pub, priv = witness

    setup = Setup(plonkish)
    pk, vk = setup.generate()

    prover = Prover(pk)
    proof = prover.prove(pub, priv)

    hex_proof = proof.to_hex()
    verifier = Verifier(vk)
    assert verifier.verify(Proof.from_hex(hex_proof), pub)


def test_plonk_bls12_381(plonkish_data_bls12_381):

    plonkish, witness = plonkish_data_bls12_381
    pub, priv = witness

    setup = Setup(plonkish, curve="BLS12_381")
    pk, vk = setup.generate()

    prover = Prover(pk)
    proof = prover.prove(pub, priv)

    hex_proof = proof.to_hex()
    verifier = Verifier(vk)
    assert verifier.verify(Proof.from_hex(hex_proof, "BLS12_381"), pub)

def test_key_serialization_bn254(plonkish_data_bn254):
    pass


def test_key_serialization_bls12_381(plonkish_data_bls12_381):
    pass
