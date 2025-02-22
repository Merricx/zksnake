import pytest

from zksnake.constant import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD
from zksnake.ecc import EllipticCurve
from zksnake.arithmetization import Var, ConstraintSystem, R1CS
from zksnake.groth16 import Groth16, Proof, ProvingKey, VerifyingKey


@pytest.fixture
def r1cs_data_bn254():

    x = Var("x")
    y = Var("y")
    v1 = Var("v1")

    cs = ConstraintSystem(["x"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    r1cs = R1CS(cs)
    r1cs.compile()

    pub, priv = r1cs.generate_witness(r1cs.solve({"x": 3}))

    return r1cs, (pub, priv)


@pytest.fixture
def r1cs_data_bls12_381():
    x = Var("x")
    y = Var("y")
    v1 = Var("v1")

    cs = ConstraintSystem(["x"], ["y"], BLS12_381_SCALAR_FIELD)
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    r1cs = R1CS(cs, "BLS12_381")
    r1cs.compile()

    pub, priv = r1cs.generate_witness(r1cs.solve({"x": 3}))

    return r1cs, (pub, priv)


@pytest.fixture
def trusted_setup_bn254(r1cs_data_bn254):
    r1cs, _ = r1cs_data_bn254

    groth16 = Groth16(r1cs)
    groth16.setup()

    return groth16


@pytest.fixture
def trusted_setup_bls12_381(r1cs_data_bls12_381):
    r1cs, _ = r1cs_data_bls12_381

    groth16 = Groth16(r1cs, "BLS12_381")
    groth16.setup()

    return groth16


def test_groth16_bn254(r1cs_data_bn254):

    r1cs, witness = r1cs_data_bn254
    pub, priv = witness

    groth16 = Groth16(r1cs)
    groth16.setup()

    proof = groth16.prove(pub, priv)
    assert groth16.verify(proof, pub)


def test_groth16_bls12_381(r1cs_data_bls12_381):

    r1cs, witness = r1cs_data_bls12_381
    pub, priv = witness

    groth16 = Groth16(r1cs, "BLS12_381")
    groth16.setup()

    proof = groth16.prove(pub, priv)
    assert groth16.verify(proof, pub)


def test_groth16_from_circom():

    r1cs = R1CS.from_file(
        "./tests/stub/test_poseidon.r1cs", "./tests/stub/test_poseidon.sym"
    )

    solved = r1cs.solve(
        {
            "main.a": 1,
            "main.b": 2,
            "main.c": 3,
        },
    )

    r1cs.compile()

    pub, priv = r1cs.generate_witness(solved)

    groth16 = Groth16(r1cs)
    groth16.setup()

    proof = groth16.prove(pub, priv)

    assert groth16.verify(proof, pub)


def test_unused_public_input():

    x = Var("x")
    y = Var("y")
    v1 = Var("v1")
    unused = Var("unused")

    cs = ConstraintSystem(["x", "unused"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.add_constraint(unused * 0 == 0)
    cs.set_public(unused)
    cs.set_public(y)

    r1cs = R1CS(cs)
    r1cs.compile()
    pub, priv = r1cs.generate_witness(r1cs.solve({"x": 3, "unused": 1337}))

    groth16 = Groth16(r1cs)
    groth16.setup()

    proof = groth16.prove(pub, priv)

    # try to forge public witness with same proof
    assert groth16.verify(proof, pub)
    pub[2] = 1330000000
    assert groth16.verify(proof, pub) is False


def test_proof_serialization_bn254():

    E = EllipticCurve("BN254")
    G1 = E.G1()
    G2 = E.G2()

    A = G1 * 1337
    B = G2 * 133337
    C = G1 * 1333337

    proof1 = Proof(A, B, C)

    hex_proof = proof1.to_bytes()

    proof2 = Proof.from_bytes(hex_proof)

    assert str(proof1) == str(proof2)


def test_proof_serialization_bls12_381():

    E = EllipticCurve("BLS12_381")
    G1 = E.G1()
    G2 = E.G2()

    A = G1 * 1337
    B = G2 * 133337
    C = G1 * 1333337

    proof1 = Proof(A, B, C)

    hex_proof = proof1.to_bytes()

    proof2 = Proof.from_bytes(hex_proof, "BLS12_381")

    assert str(proof1) == str(proof2)


def test_key_serialization_bn254(trusted_setup_bn254):
    pk = trusted_setup_bn254.proving_key
    vk = trusted_setup_bn254.verifying_key

    pk_bytes = pk.to_bytes()
    pk2 = ProvingKey.from_bytes(pk_bytes, crv="BN254")
    assert pk_bytes == pk2.to_bytes()

    vk_bytes = vk.to_bytes()
    vk2 = VerifyingKey.from_bytes(vk_bytes, crv="BN254")
    assert vk_bytes == vk2.to_bytes()


def test_key_serialization_bls12_381(trusted_setup_bls12_381):
    pk = trusted_setup_bls12_381.proving_key
    vk = trusted_setup_bls12_381.verifying_key

    pk_bytes = pk.to_bytes()
    pk2 = ProvingKey.from_bytes(pk_bytes, crv="BLS12_381")
    assert pk_bytes == pk2.to_bytes()

    vk_bytes = vk.to_bytes()
    vk2 = VerifyingKey.from_bytes(vk_bytes, crv="BLS12_381")
    assert vk_bytes == vk2.to_bytes()
