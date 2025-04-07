import pytest
import random
from zksnake.subprotocol.fri import FRI
from zksnake.constant import BN254_SCALAR_FIELD


def test_fri_low():

    fri = FRI(16, BN254_SCALAR_FIELD, folding_factor=2, last_layer_degree_bound=2)

    # pre-seeded to avoid long Proof of Work
    random.seed("test")
    commitment, proof = fri.prove(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)]
    )

    assert fri.verify(commitment, proof)


def test_fri_high():

    fri = FRI(128, BN254_SCALAR_FIELD, folding_factor=8, last_layer_degree_bound=15)

    # pre-seeded to avoid long Proof of Work
    random.seed("test")
    commitment, proof = fri.prove(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(128)]
    )

    assert fri.verify(commitment, proof)
