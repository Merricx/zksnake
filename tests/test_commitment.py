import random
from zksnake.commitment.polynomial import KZG, IPA, MultiOpeningQuery
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
