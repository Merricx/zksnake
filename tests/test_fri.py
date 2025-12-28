import pytest
import random
from zksnake.subprotocol.ldt import FRI
from zksnake.polynomial import Polynomial
from zksnake.constant import BN254_SCALAR_FIELD


def test_fri_low():

    fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )
    print(f"FRI security bits: {fri.get_security_bits()}")

    # pre-seeded to avoid unpredictable long Proof of Work
    random.seed("test")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )
    commitment, proof = fri.prove(poly)

    assert fri.verify(commitment, proof)


def test_fri_high():

    fri = FRI(
        2047,
        BN254_SCALAR_FIELD,
        blowup_factor=16,
        folding_factor=8,
        last_layer_degree_bound=4,
        num_queries=15,
    )
    print(f"FRI security bits: {fri.get_security_bits()}")

    # pre-seeded to avoid unpredictable long Proof of Work
    random.seed("test")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(1024)],
        BN254_SCALAR_FIELD,
    )
    commitment, proof = fri.prove(poly)

    assert fri.verify(commitment, proof)
