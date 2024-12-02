import pytest

from zksnake.ecc import EllipticCurve
from zksnake.symbolic import Symbol
from zksnake.arithmetization.r1cs import ConstraintSystem
from zksnake.groth16 import Prover, Proof, ProvingKey, Setup, Verifier, VerifyingKey


@pytest.fixture
def qap_data_bn254():

    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")

    cs = ConstraintSystem(["x"], ["y"])
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    pub, priv = cs.solve({"x": 3}, {"y": 35})

    qap = cs.compile()

    return qap, (pub, priv)


@pytest.fixture
def qap_data_bls12_381():
    x = Symbol("x")
    y = Symbol("y")
    v1 = Symbol("v1")

    cs = ConstraintSystem(["x"], ["y"], "BLS12_381")
    cs.add_constraint(v1 == x * x)
    cs.add_constraint(y - 5 - x == v1 * x)
    cs.set_public(y)

    pub, priv = cs.solve({"x": 3}, {"y": 35})

    qap = cs.compile()

    return qap, (pub, priv)


@pytest.fixture
def trusted_setup_bn254(qap_data_bn254):
    qap, _ = qap_data_bn254

    setup = Setup(qap)
    pk, vk = setup.generate()

    return pk, vk


@pytest.fixture
def trusted_setup_bls12_381(qap_data_bls12_381):
    qap, _ = qap_data_bls12_381

    setup = Setup(qap, "BLS12_381")
    pk, vk = setup.generate()

    return pk, vk


def test_groth16_bn254(qap_data_bn254):

    qap, witness = qap_data_bn254
    pub, priv = witness

    setup = Setup(qap)
    pk, vk = setup.generate()

    prover = Prover(qap, pk)
    proof = prover.prove(pub, priv)

    verifier = Verifier(vk)
    assert verifier.verify(proof, pub)


def test_groth16_bls12_381(qap_data_bls12_381):

    qap, witness = qap_data_bls12_381
    pub, priv = witness

    setup = Setup(qap, "BLS12_381")
    pk, vk = setup.generate()

    prover = Prover(qap, pk, "BLS12_381")
    proof = prover.prove(pub, priv)

    verifier = Verifier(vk, "BLS12_381")
    assert verifier.verify(proof, pub)


def test_groth16_from_circom():

    cs = ConstraintSystem.from_file(
        "./tests/stub/test_poseidon.r1cs", "./tests/stub/test_poseidon.sym"
    )

    pub, priv = cs.solve(
        {
            "main.a": 1,
            "main.b": 2,
            "main.c": 3,
        },
        {
            "main.h": 6542985608222806190361240322586112750744169038454362455181422643027100751666
        },
    )

    qap = cs.compile()

    setup = Setup(qap)

    pkey, vkey = setup.generate()

    prover = Prover(qap, pkey)
    verifier = Verifier(vkey)

    proof = prover.prove(pub, priv)

    assert verifier.verify(proof, pub)


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

    # try to forge public witness with same proof
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
