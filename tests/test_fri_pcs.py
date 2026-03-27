import pytest
import random
from zksnake.commitment.polynomial.fri import FRI_PCS
from zksnake.commitment.polynomial.base import MultiOpeningQuery
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


def _make_pcs():
    return FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )


def test_fri_pcs_multi_open():
    """Multiple polynomials opened at multiple points."""

    pcs = _make_pcs()
    random.seed("test_multi")
    p = BN254_SCALAR_FIELD

    poly1 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    poly2 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    poly3 = Polynomial([random.randint(1, p - 1) for _ in range(8)], p)

    c1, _ = pcs.commit(poly1)
    c2, _ = pcs.commit(poly2)
    c3, _ = pcs.commit(poly3)

    x = 123
    y = 456

    query = MultiOpeningQuery()
    query.add_polynomial(poly1, c1)
    query.add_polynomial(poly2, c2)
    query.add_polynomial(poly3, c3)

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, verifier_query = pcs.multi_open(query)

    assert pcs.multi_verify(verifier_query, proof)


def test_fri_pcs_multi_open_single_poly():
    """Single polynomial opened at two points (degenerates gracefully)."""

    pcs = _make_pcs()
    random.seed("test_multi_single")
    p = BN254_SCALAR_FIELD

    poly = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    c, _ = pcs.commit(poly)

    query = MultiOpeningQuery()
    query.add_polynomial(poly, c)
    query.prover_query(poly, 10)
    query.prover_query(poly, 20)

    proof, verifier_query = pcs.multi_open(query)

    assert pcs.multi_verify(verifier_query, proof)


def test_fri_pcs_multi_open_rejects_tampered_evaluation():
    """Tampering with a claimed evaluation causes verification failure."""

    pcs = _make_pcs()
    random.seed("test_multi_tamper")
    p = BN254_SCALAR_FIELD

    poly1 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    poly2 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)

    c1, _ = pcs.commit(poly1)
    c2, _ = pcs.commit(poly2)

    query = MultiOpeningQuery()
    query.add_polynomial(poly1, c1)
    query.add_polynomial(poly2, c2)
    query.prover_query(poly1, 42)
    query.prover_query(poly2, 42)

    proof, verifier_query = pcs.multi_open(query)

    # Tamper with one evaluation in the verifier query
    for pt in verifier_query.evaluations:
        for idx in verifier_query.evaluations[pt]:
            verifier_query.evaluations[pt][idx] = (
                verifier_query.evaluations[pt][idx] + 1
            ) % p
            break
        break

    with pytest.raises(ValueError):
        pcs.multi_verify(verifier_query, proof)


def test_fri_pcs_multi_open_ordering_mismatch():
    """Verify multi_open works when first-appearance order of commitments
    differs from the polynomial list order."""

    pcs = _make_pcs()
    random.seed("test_ordering")
    p = BN254_SCALAR_FIELD

    poly1 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    poly2 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)

    c1, _ = pcs.commit(poly1)
    c2, _ = pcs.commit(poly2)

    x = 100
    y = 200

    # Add polynomials in order [poly1, poly2]
    query = MultiOpeningQuery()
    query.add_polynomial(poly1, c1)
    query.add_polynomial(poly2, c2)

    # But open poly2 first — so first-appearance commitment order is [c2, c1]
    query.prover_query(poly2, x)
    query.prover_query(poly1, y)

    proof, verifier_query = pcs.multi_open(query)

    assert pcs.multi_verify(verifier_query, proof)


def test_fri_pcs_multi_open_point_on_domain():
    """Verify multi_open works when an opening point lies on the evaluation domain
    (would cause division by zero)."""

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        offset=1,  # offset=1 means domain point ω^0 = 1 is in the coset
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_domain_point")
    p = BN254_SCALAR_FIELD

    poly1 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    poly2 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)

    c1, _ = pcs.commit(poly1)
    c2, _ = pcs.commit(poly2)

    # point=1 is on the evaluation domain when offset=1 (ω^0 * offset = 1)
    query = MultiOpeningQuery()
    query.add_polynomial(poly1, c1)
    query.add_polynomial(poly2, c2)
    query.prover_query(poly1, 1)
    query.prover_query(poly2, 1)

    proof, verifier_query = pcs.multi_open(query)

    assert pcs.multi_verify(verifier_query, proof)


def test_fri_pcs_with_independent_verifier_query():

    pcs = FRI_PCS(
        15,
        BN254_SCALAR_FIELD,
        blowup_factor=2,
        folding_factor=2,
        last_layer_degree_bound=2,
        num_queries=5,
    )

    random.seed("test_independent_query")
    p = BN254_SCALAR_FIELD

    poly1 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)
    poly2 = Polynomial([random.randint(1, p - 1) for _ in range(16)], p)

    c1, _ = pcs.commit(poly1)
    c2, _ = pcs.commit(poly2)

    x = 123
    y = 456

    prover_query = MultiOpeningQuery()
    prover_query.add_polynomial(poly2, c2)
    prover_query.add_polynomial(poly1, c1)

    prover_query.prover_query(poly1, x)
    prover_query.prover_query(poly2, x)
    prover_query.prover_query(poly2, y)

    proof, query_result = pcs.multi_open(prover_query)

    # Verifier independently constructs the verifier query (instead of using query_result from multi_open)
    verifier_query = MultiOpeningQuery(True)
    verifier_query.add_commitment(c2)
    verifier_query.add_commitment(c1)

    verifier_query.verifier_query(c1, x, query_result.get_evaluation(c1, x))
    verifier_query.verifier_query(c2, x, query_result.get_evaluation(c2, x))
    verifier_query.verifier_query(c2, y, query_result.get_evaluation(c2, y))

    assert pcs.multi_verify(verifier_query, proof)
