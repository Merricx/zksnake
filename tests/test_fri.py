import pytest
import random
from zksnake.subprotocol.ldt import FRI
from zksnake.polynomial import Polynomial
from zksnake.constant import BN254_SCALAR_FIELD
from zksnake.transcript import FiatShamirTranscript


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


def test_fri_rejects_random_codeword():

    fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )

    random.seed(0)
    codeword = [random.randint(0, BN254_SCALAR_FIELD - 1) for _ in range(fri.domain)]

    transcript = FiatShamirTranscript(fri.name, fri.order)
    fri.init_transcript(transcript)
    commitment, codewords = fri.commit(codeword, transcript)
    proof = fri.query(codewords, transcript)

    with pytest.raises(ValueError):
        fri.verify(commitment, proof)


def test_fri_with_coset_offset():

    fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        offset=7,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_offset")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )
    commitment, proof = fri.prove(poly)

    assert fri.verify(commitment, proof)


def test_fri_rejects_tampered_commitment():

    fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )

    random.seed("test_tamper")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )
    commitment, proof = fri.prove(poly)

    # tamper with the last polynomial in the commitment
    tampered_commitment = commitment[:-1] + [[0] * len(commitment[-1])]

    with pytest.raises(ValueError):
        fri.verify(tampered_commitment, proof)


def test_fri_rejects_wrong_offset():

    random.seed(1)
    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    prover_fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        offset=1,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )
    verifier_fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        offset=7,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )

    commitment, proof = prover_fri.prove(poly)

    with pytest.raises(ValueError):
        verifier_fri.verify(commitment, proof)


def test_fri_rejects_zero_offset_mod_field():

    with pytest.raises(ValueError):
        FRI(
            15,
            BN254_SCALAR_FIELD,
            offset=BN254_SCALAR_FIELD,
            blowup_factor=2,
            folding_factor=2,
            last_layer_degree_bound=2,
            num_queries=2,
        )


def test_fri_normalizes_equivalent_offsets():

    random.seed("test_normalized_offset")
    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    base_fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        offset=7,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )
    normalized_fri = FRI(
        15,
        BN254_SCALAR_FIELD,
        offset=BN254_SCALAR_FIELD + 7,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )

    base_commitment, base_proof = base_fri.prove(poly)
    normalized_commitment, normalized_proof = normalized_fri.prove(poly)

    assert base_commitment == normalized_commitment
    assert base_proof == normalized_proof
