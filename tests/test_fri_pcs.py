import pytest
import random
from zksnake.commitment.polynomial.fri import FRI_PCS
from zksnake.polynomial import Polynomial
from zksnake.constant import BN254_SCALAR_FIELD


def test_fri_pcs_basic():

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_pcs")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    commitment, prover_state = pcs.commit(poly)
    point = 42
    proof, evaluation = pcs.open(poly, point, commitment, prover_state)

    assert evaluation == poly(point)
    assert pcs.verify(commitment, proof, point, evaluation)


def test_fri_pcs_with_offset():

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        offset=7,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_pcs_offset")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    commitment, prover_state = pcs.commit(poly)
    point = 123456
    proof, evaluation = pcs.open(poly, point, commitment, prover_state)

    assert evaluation == poly(point)
    assert pcs.verify(commitment, proof, point, evaluation)


def test_fri_pcs_rejects_wrong_evaluation():

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_pcs_wrong_eval")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    commitment, prover_state = pcs.commit(poly)
    point = 42
    proof, evaluation = pcs.open(poly, point, commitment, prover_state)

    # tamper with the claimed evaluation
    wrong_evaluation = (evaluation + 1) % BN254_SCALAR_FIELD

    with pytest.raises(ValueError):
        pcs.verify(commitment, proof, point, wrong_evaluation)


def test_fri_pcs_rejects_wrong_point():

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_pcs_wrong_point")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    commitment, prover_state = pcs.commit(poly)
    point = 42
    proof, evaluation = pcs.open(poly, point, commitment, prover_state)

    # verify at a different point
    with pytest.raises(ValueError):
        pcs.verify(commitment, proof, point + 1, evaluation)


def test_fri_pcs_zero_fri_rounds():
    """FRI_PCS works when last_layer_degree_bound causes zero Merkle rounds."""

    # domain = blowup_factor * (max_degree + 1) = 2 * 16 = 32
    # last_layer_degree_bound = 31 >= domain - 1, so FRI sends q in the clear
    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=31,
        num_queries=5,
    )

    random.seed("test_pcs_zero_rounds")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    commitment, prover_state = pcs.commit(poly)
    point = 42
    proof, evaluation = pcs.open(poly, point, commitment, prover_state)

    assert evaluation == poly(point)
    assert pcs.verify(commitment, proof, point, evaluation)


def test_fri_pcs_rejects_malformed_proof():
    """Malformed proofs raise ValueError, not IndexError."""

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=2,
    )

    random.seed("test_pcs_malformed")

    poly = Polynomial(
        [random.randint(1, BN254_SCALAR_FIELD - 1) for _ in range(16)],
        BN254_SCALAR_FIELD,
    )

    commitment, prover_state = pcs.commit(poly)
    point = 42
    proof, evaluation = pcs.open(poly, point, commitment, prover_state)

    # wrong length proof
    with pytest.raises(ValueError):
        pcs.verify(commitment, [proof[0]], point, evaluation)

    # truncated f_openings (2 queries but only 1 opening)
    truncated = [proof[0], proof[1], proof[2][:1], proof[3]]
    with pytest.raises(ValueError):
        pcs.verify(commitment, truncated, point, evaluation)

    # truncated q_query_openings
    truncated = [proof[0], proof[1], proof[2], proof[3][:1]]
    with pytest.raises(ValueError):
        pcs.verify(commitment, truncated, point, evaluation)

    # truncated q layers within a query
    bad_q_openings = [proof[3][0][:-1], proof[3][1]]
    truncated = [proof[0], proof[1], proof[2], bad_q_openings]
    with pytest.raises(ValueError):
        pcs.verify(commitment, truncated, point, evaluation)
