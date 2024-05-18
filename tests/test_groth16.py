import pytest

from zksnake.ecc import EllipticCurve
from zksnake.qap import QAP
from zksnake.r1cs import ConstraintSystem
from zksnake.groth16 import Prover, Proof, Setup, Verifier


@pytest.fixture
def qap_data_bn254():

    return {
        "U": [
            [0, 0],
            [0, 0],
            [
                2,
                21888242871839275222246405745257275088548364400416034343698204186575808495616,
            ],
            [
                21888242871839275222246405745257275088548364400416034343698204186575808495616,
                1,
            ],
        ],
        "V": [[0, 0], [0, 0], [1, 0], [0, 0]],
        "W": [
            [
                5,
                21888242871839275222246405745257275088548364400416034343698204186575808495612,
            ],
            [
                21888242871839275222246405745257275088548364400416034343698204186575808495616,
                1,
            ],
            [
                1,
                21888242871839275222246405745257275088548364400416034343698204186575808495616,
            ],
            [
                2,
                21888242871839275222246405745257275088548364400416034343698204186575808495616,
            ],
        ],
    }


@pytest.fixture
def qap_data_bls12_381():
    return {
        "U": [
            [0, 0],
            [0, 0],
            [
                2,
                52435875175126190479447740508185965837690552500527637822603658699938581184512,
            ],
            [
                52435875175126190479447740508185965837690552500527637822603658699938581184512,
                1,
            ],
        ],
        "V": [[0, 0], [0, 0], [1, 0], [0, 0]],
        "W": [
            [
                5,
                52435875175126190479447740508185965837690552500527637822603658699938581184508,
            ],
            [
                52435875175126190479447740508185965837690552500527637822603658699938581184512,
                1,
            ],
            [
                1,
                52435875175126190479447740508185965837690552500527637822603658699938581184512,
            ],
            [
                2,
                52435875175126190479447740508185965837690552500527637822603658699938581184512,
            ],
        ],
    }


def test_groth16_bn254(qap_data_bn254):

    qap = QAP(EllipticCurve("BN254").order)

    qap.U = qap_data_bn254["U"]
    qap.V = qap_data_bn254["V"]
    qap.W = qap_data_bn254["W"]
    qap.n_public = 2

    setup = Setup(qap)
    pk, vk = setup.generate()

    pub = [1, 35]
    priv = [3, 9]

    prover = Prover(qap, pk)
    proof = prover.prove(pub, priv)

    verifier = Verifier(vk)
    assert verifier.verify(proof, pub)


def test_groth16_bls12_381(qap_data_bls12_381):

    qap = QAP(EllipticCurve("BLS12_381").order)

    qap.U = qap_data_bls12_381["U"]
    qap.V = qap_data_bls12_381["V"]
    qap.W = qap_data_bls12_381["W"]
    qap.n_public = 2

    setup = Setup(qap, "BLS12_381")
    pk, vk = setup.generate()

    pub = [1, 35]
    priv = [3, 9]

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
