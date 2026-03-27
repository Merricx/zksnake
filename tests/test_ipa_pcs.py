import random
from zksnake.commitment.polynomial import IPA, MultiOpeningQuery
from zksnake.polynomial import Polynomial


def test_ipa_pcs():

    ipa = IPA(4, "BN254")
    ipa.setup()

    poly = Polynomial([1, 2, 22, 7], ipa.order)

    blinding = random.randint(1, ipa.order)
    commitment = ipa.commit(poly, blinding)

    point = random.randint(1, ipa.order)

    proof, evaluation = ipa.open(poly, point, commitment, blinding)

    assert ipa.verify(commitment, proof, point, evaluation)


def test_multi_ipa_pcs():

    ipa = IPA(4, "BN254")
    ipa.setup()

    poly1 = Polynomial([1, 3, 3, 7], ipa.order)
    poly2 = Polynomial([1, 2, 3, 4], ipa.order)
    poly3 = Polynomial([1, 2, 3, 0], ipa.order)

    blind1 = random.randint(1, ipa.order)
    blind2 = random.randint(1, ipa.order)
    blind3 = random.randint(1, ipa.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()

    query.add_polynomial(poly1, ipa.commit(poly1, blind1), blind1)
    query.add_polynomial(poly2, ipa.commit(poly2, blind2), blind2)
    query.add_polynomial(poly3, ipa.commit(poly3, blind3), blind3)

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, verifier_query = ipa.multi_open(query)

    assert ipa.multi_verify(verifier_query, proof)


def test_ordering_multi_ipa_pcs():

    ipa = IPA(4, "BN254")
    ipa.setup()

    poly1 = Polynomial([1, 3, 3, 7], ipa.order)
    poly2 = Polynomial([1, 2, 3, 4], ipa.order)
    poly3 = Polynomial([1, 2, 3, 0], ipa.order)

    blind1 = random.randint(1, ipa.order)
    blind2 = random.randint(1, ipa.order)
    blind3 = random.randint(1, ipa.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()

    # add in different order than polynomial list
    query.add_polynomial(poly2, ipa.commit(poly2, blind2), blind2)
    query.add_polynomial(poly3, ipa.commit(poly3, blind3), blind3)
    query.add_polynomial(poly1, ipa.commit(poly1, blind1), blind1)

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, verifier_query = ipa.multi_open(query)

    assert ipa.multi_verify(verifier_query, proof)


def test_ipa_with_independent_verifier_query():

    ipa = IPA(4, "BN254")
    ipa.setup()

    poly1 = Polynomial([1, 3, 3, 7], ipa.order)
    poly2 = Polynomial([1, 2, 3, 4], ipa.order)
    poly3 = Polynomial([1, 2, 3, 0], ipa.order)

    blind1 = random.randint(1, ipa.order)
    blind2 = random.randint(1, ipa.order)
    blind3 = random.randint(1, ipa.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()

    commit1 = ipa.commit(poly1, blind1)
    commit2 = ipa.commit(poly2, blind2)
    commit3 = ipa.commit(poly3, blind3)

    # add in different order than polynomial list
    query.add_polynomial(poly2, commit2, blind2)
    query.add_polynomial(poly3, commit3, blind3)
    query.add_polynomial(poly1, commit1, blind1)

    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)

    proof, query_result = ipa.multi_open(query)

    verifier_query = MultiOpeningQuery(True)
    verifier_query.add_commitment(commit2)
    verifier_query.add_commitment(commit3)
    verifier_query.add_commitment(commit1)

    verifier_query.verifier_query(commit1, x, query_result.get_evaluation(commit1, x))
    verifier_query.verifier_query(commit2, x, query_result.get_evaluation(commit2, x))
    verifier_query.verifier_query(commit2, y, query_result.get_evaluation(commit2, y))
    verifier_query.verifier_query(commit3, x, query_result.get_evaluation(commit3, x))
    verifier_query.verifier_query(commit3, y, query_result.get_evaluation(commit3, y))
    assert ipa.multi_verify(verifier_query, proof)
