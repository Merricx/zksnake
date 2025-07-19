import pytest
import random
from zksnake.subprotocol.fri import FRI
from zksnake.polynomial import Polynomial
from zksnake.commitment.polynomial.fri import FRI_PCS
from zksnake.constant import BN254_SCALAR_FIELD
from zksnake.transcript import FiatShamirTranscript


def test_fri_low():

    fri = FRI(16, BN254_SCALAR_FIELD, folding_factor=2, last_layer_degree_bound=2)

    # pre-seeded to avoid long Proof of Work
    random.seed("test")
    commitment, proof = fri.prove(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)]
    )

    assert fri.verify(commitment, proof)


def test_fri_high():

    fri = FRI(2048, BN254_SCALAR_FIELD, folding_factor=4, last_layer_degree_bound=1)

    # pre-seeded to avoid long Proof of Work
    random.seed("test")
    commitment, proof = fri.prove(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(2048)]
    )

    assert fri.verify(commitment, proof)


def test_fri_pcs():

    fri = FRI_PCS(16, BN254_SCALAR_FIELD, folding_factor=2, last_layer_degree_bound=2)
    # pre-seeded to avoid long Proof of Work
    random.seed("test")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    transcript = FiatShamirTranscript(b"FRI", BN254_SCALAR_FIELD)
    commitment, codewords = fri.commit(poly, 1337, transcript)
    proof = fri.open(codewords, transcript)

    transcript = FiatShamirTranscript(b"FRI", BN254_SCALAR_FIELD)
    assert fri.verify(commitment, proof, transcript)
