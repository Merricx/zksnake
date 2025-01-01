import pytest

from zksnake.constant import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD
from zksnake.ecc import EllipticCurve
from zksnake.arithmetization import Var, ConstraintSystem, R1CS
from zksnake.groth16 import Prover, Proof, ProvingKey, Setup, Verifier, VerifyingKey


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

    pub, priv = r1cs.generate_witness(cs.solve({"x": 3}))

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

    pub, priv = r1cs.generate_witness(cs.solve({"x": 3}))

    return r1cs, (pub, priv)


@pytest.fixture
def trusted_setup_bn254(r1cs_data_bn254):
    r1cs, _ = r1cs_data_bn254

    setup = Setup(r1cs)
    pk, vk = setup.generate()

    return pk, vk


@pytest.fixture
def trusted_setup_bls12_381(r1cs_data_bls12_381):
    r1cs, _ = r1cs_data_bls12_381

    setup = Setup(r1cs, "BLS12_381")
    pk, vk = setup.generate()

    return pk, vk


def test_groth16_bn254(r1cs_data_bn254):

    r1cs, witness = r1cs_data_bn254
    pub, priv = witness

    setup = Setup(r1cs)
    pk, vk = setup.generate()

    prover = Prover(r1cs, pk)
    proof = prover.prove(pub, priv)

    verifier = Verifier(vk)
    assert verifier.verify(proof, pub)


def test_groth16_bls12_381(r1cs_data_bls12_381):

    r1cs, witness = r1cs_data_bls12_381
    pub, priv = witness

    setup = Setup(r1cs, "BLS12_381")
    pk, vk = setup.generate()

    prover = Prover(r1cs, pk, "BLS12_381")
    proof = prover.prove(pub, priv)

    verifier = Verifier(vk, "BLS12_381")
    assert verifier.verify(proof, pub)


def test_groth16_from_circom():

    cs = R1CS.from_file(
        "./tests/stub/test_poseidon.r1cs", "./tests/stub/test_poseidon.sym"
    )

    solved = cs.solve(
        {
            "main.a": 1,
            "main.b": 2,
            "main.c": 3,
        },
    )

    r1cs = R1CS(cs)
    r1cs.compile()

    pub, priv = r1cs.generate_witness(solved)

    setup = Setup(r1cs)

    pkey, vkey = setup.generate()

    prover = Prover(r1cs, pkey)
    verifier = Verifier(vkey)

    proof = prover.prove(pub, priv)

    assert verifier.verify(proof, pub)


def test_unused_public_input():

    x = Var("x")
    y = Var("y")
    v1 = Var("v1")
    unused = Var("unused")

    cs = ConstraintSystem(["x", "unused"], ["y"], BN254_SCALAR_FIELD)
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.add_constraint(unused*0 == 0)
    cs.set_public(unused)
    cs.set_public(y)


    r1cs = R1CS(cs)
    r1cs.compile()
    pub, priv = r1cs.generate_witness(cs.solve({"x": 3, "unused": 1337}))

    setup = Setup(r1cs)
    pkey, vkey = setup.generate()

    prover = Prover(r1cs, pkey)
    verifier = Verifier(vkey)

    proof = prover.prove(pub, priv)

    # try to forge public witness with same proof
    assert verifier.verify(proof, pub)
    pub[2] = 1330000000
    assert verifier.verify(proof, pub) is False


def test_proof_serialization_bn254():

    E = EllipticCurve("BN254")
    G1 = E.G1()
    G2 = E.G2()

    A = G1 * 1337
    B = G2 * 133337
    C = G1 * 1333337

    proof1 = Proof(A, B, C)

    hex_proof = proof1.to_hex()

    proof2 = Proof.from_hex(hex_proof)

    assert str(proof1) == str(proof2)


def test_proof_serialization_bls12_381():

    E = EllipticCurve("BLS12_381")
    G1 = E.G1()
    G2 = E.G2()

    A = G1 * 1337
    B = G2 * 133337
    C = G1 * 1333337

    proof1 = Proof(A, B, C)

    hex_proof = proof1.to_hex()

    proof2 = Proof.from_hex(hex_proof, "BLS12_381")

    assert str(proof1) == str(proof2)


def test_key_serialization_bn254(trusted_setup_bn254):
    pk, vk = trusted_setup_bn254

    pk_bytes = pk.to_bytes()
    pk2 = ProvingKey.from_bytes(pk_bytes, crv="BN254")
    assert pk_bytes == pk2.to_bytes()

    vk_hex = vk.to_hex()
    vk2 = VerifyingKey.from_hex(vk_hex, crv="BN254")
    assert vk_hex == vk2.to_hex()


def test_key_serialization_bls12_381(trusted_setup_bls12_381):
    pk, vk = trusted_setup_bls12_381

    pk_bytes = pk.to_bytes()
    pk2 = ProvingKey.from_bytes(pk_bytes, crv="BLS12_381")
    assert pk_bytes == pk2.to_bytes()

    vk_hex = vk.to_hex()
    vk2 = VerifyingKey.from_hex(vk_hex, crv="BLS12_381")
    assert vk_hex == vk2.to_hex()
