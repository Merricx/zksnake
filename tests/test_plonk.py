import pytest

from zksnake.arithmetization.plonkish import Plonkish
from zksnake.constant import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD
from zksnake.arithmetization import Var, ConstraintSystem
from zksnake.plonk import Plonk, Proof, ProvingKey, VerifyingKey


@pytest.fixture
def plonkish_data_bn254():

    x = Var("x")
    y = Var("y")
    z = Var('z')
    v0 = Var('v0')
    v1 = Var('v1')
    v2 = Var('v2')
    v3 = Var('v3')
    v4 = Var('v4')
    v5 = Var('v5')
    v6 = Var('v6')

    cs = ConstraintSystem(["x"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(z  == x)
    cs.add_constraint(v0 == z*z)
    cs.add_constraint(v1 == z*z)
    cs.add_constraint(v2 == v1 * x)
    cs.add_constraint(v3 == v0 * 2 * 3)
    cs.add_constraint(v4 == 2*v1 * v2*3)
    cs.add_constraint(v5 == 2*v3 - v4)
    cs.add_constraint(v6 == 2 + v5 + 3)
    cs.add_constraint(y == v6 + v4 + 1337)
    cs.set_public(y)
    cs.set_public(z)

    plonkish = Plonkish(cs)
    plonkish.compile()
    pub, priv = plonkish.generate_witness(cs.solve({"x": 3}))
    
    assert plonkish.is_sat(pub, priv)

    return plonkish, (pub, priv)

@pytest.fixture
def plonkish_data_bls12_381():

    x = Var("x")
    y = Var("y")
    z = Var('z')
    v0 = Var('v0')
    v1 = Var('v1')
    v2 = Var('v2')
    v3 = Var('v3')
    v4 = Var('v4')
    v5 = Var('v5')
    v6 = Var('v6')

    cs = ConstraintSystem(["x"], ["y"], BLS12_381_SCALAR_FIELD)
    cs.add_constraint(z  == x)
    cs.add_constraint(v0 == z*z)
    cs.add_constraint(v1 == z*z)
    cs.add_constraint(v2 == v1 * x)
    cs.add_constraint(v3 == v0 * 2 * 3)
    cs.add_constraint(v4 == 2*v1 * v2*3)
    cs.add_constraint(v5 == 2*v3 - v4)
    cs.add_constraint(v6 == 2 + v5 + 3)
    cs.add_constraint(y == v6 + v4 + 1337)
    cs.set_public(y)
    cs.set_public(z)

    plonkish = Plonkish(cs, "BLS12_381")
    plonkish.compile()

    pub, priv = plonkish.generate_witness(cs.solve({"x": 1337}))
    assert plonkish.is_sat(pub, priv)

    return plonkish, (pub, priv)

def test_plonk_bn254(plonkish_data_bn254):

    plonkish, witness = plonkish_data_bn254
    pub, priv = witness

    plonk = Plonk(plonkish)
    plonk.setup()

    proof = plonk.prove(pub, priv)

    proof_bytes = proof.to_bytes()
    assert plonk.verify(Proof.from_bytes(proof_bytes), pub)


def test_plonk_bls12_381(plonkish_data_bls12_381):

    plonkish, witness = plonkish_data_bls12_381
    pub, priv = witness

    plonk = Plonk(plonkish, curve="BLS12_381")
    plonk.setup()

    proof = plonk.prove(pub, priv)

    proof_bytes = proof.to_bytes()
    assert plonk.verify(Proof.from_bytes(proof_bytes, "BLS12_381"), pub)

def test_key_serialization_bn254(plonkish_data_bn254):

    plonkish, _ = plonkish_data_bn254

    plonk = Plonk(plonkish)
    plonk.setup()

    pk = plonk.proving_key.to_bytes()
    vk = plonk.verifying_key.to_bytes()

    assert ProvingKey.from_bytes(pk).to_bytes() == plonk.proving_key.to_bytes()
    assert VerifyingKey.from_bytes(vk).to_bytes() == plonk.verifying_key.to_bytes()


def test_key_serialization_bls12_381(plonkish_data_bls12_381):
    
    plonkish, _ = plonkish_data_bls12_381
    
    plonk = Plonk(plonkish, 'BLS12_381')
    plonk.setup()

    pk = plonk.proving_key.to_bytes()
    vk = plonk.verifying_key.to_bytes()
    
    assert ProvingKey.from_bytes(pk, 'BLS12_381').to_bytes() == plonk.proving_key.to_bytes()
    assert VerifyingKey.from_bytes(vk, 'BLS12_381').to_bytes() == plonk.verifying_key.to_bytes()