import random
from zksnake.commitment.polynomial import KZG, MultiOpeningQuery
from zksnake.polynomial import Polynomial


def test_kzg():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly = Polynomial([1, 3, 3, 7], kzg.order)
    commitment = kzg.commit(poly)

    point = random.randint(1, kzg.order)

    proof, evaluation = kzg.open(poly, point)

    assert kzg.verify(commitment, proof, point, evaluation)


def test_multi_kzg():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly1 = Polynomial([1, 3, 3, 7], kzg.order)
    poly2 = Polynomial([1, 2, 3, 4], kzg.order)
    poly3 = Polynomial([1, 2, 3, 0], kzg.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()

    query.add_polynomial(poly1, kzg.commit(poly1))
    query.add_polynomial(poly2, kzg.commit(poly2))
    query.add_polynomial(poly3, kzg.commit(poly3))

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, verifier_query = kzg.multi_open(query)

    assert kzg.multi_verify(verifier_query, proof)


def test_ordering_multi_kzg():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly1 = Polynomial([1, 3, 3, 7], kzg.order)
    poly2 = Polynomial([1, 2, 3, 4], kzg.order)
    poly3 = Polynomial([1, 2, 3, 0], kzg.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()

    # add in different order than polynomial list
    query.add_polynomial(poly2, kzg.commit(poly2))
    query.add_polynomial(poly3, kzg.commit(poly3))
    query.add_polynomial(poly1, kzg.commit(poly1))

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, verifier_query = kzg.multi_open(query)

    assert kzg.multi_verify(verifier_query, proof)


def test_kzg_with_independent_verifier_query():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly1 = Polynomial([1, 3, 3, 7], kzg.order)
    poly2 = Polynomial([1, 2, 3, 4], kzg.order)
    poly3 = Polynomial([1, 2, 3, 0], kzg.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()

    commit1 = kzg.commit(poly1)
    commit2 = kzg.commit(poly2)
    commit3 = kzg.commit(poly3)

    # add in different order than polynomial list
    query.add_polynomial(poly2, commit2)
    query.add_polynomial(poly3, commit3)
    query.add_polynomial(poly1, commit1)

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, query_result = kzg.multi_open(query)

    verifier_query = MultiOpeningQuery(True)
    verifier_query.add_commitment(commit2)
    verifier_query.add_commitment(commit3)
    verifier_query.add_commitment(commit1)

    verifier_query.verifier_query(commit1, x, query_result.get_evaluation(commit1, x))
    verifier_query.verifier_query(commit2, x, query_result.get_evaluation(commit2, x))
    verifier_query.verifier_query(commit2, y, query_result.get_evaluation(commit2, y))
    verifier_query.verifier_query(commit3, x, query_result.get_evaluation(commit3, x))
    verifier_query.verifier_query(commit3, y, query_result.get_evaluation(commit3, y))
    assert kzg.multi_verify(verifier_query, proof)
