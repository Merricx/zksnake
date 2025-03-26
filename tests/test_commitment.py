import random
from zksnake.commitment.polynomial import KZG, Pedersen, MultiOpeningQuery
from zksnake.polynomial import Polynomial


def test_kzg():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly = Polynomial([1, 3, 3, 7], kzg.order)
    commitment = kzg.commit(poly)

    point = random.randint(1, kzg.order)

    proof, evaluation = kzg.open(poly, point)

    assert kzg.verify(commitment, proof, evaluation, point)


def test_multi_kzg():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly1 = Polynomial([1, 3, 3, 7], kzg.order)
    poly2 = Polynomial([1, 2, 3, 4], kzg.order)
    poly3 = Polynomial([1, 2, 3, 0], kzg.order)

    x = 123
    y = 1234

    query = MultiOpeningQuery()
    query.prover_query(poly1, x)
    query.prover_query(poly2, x)
    query.prover_query(poly2, y)
    query.prover_query(poly3, x)
    query.prover_query(poly3, y)
    query.commit(kzg.commit)

    proof, verifier_query = kzg.multi_open(query)

    assert kzg.multi_verify(verifier_query, proof)


def test_pedersen():

    pedersen = Pedersen(4, "BN254")
    pedersen.setup()

    poly = Polynomial([1, 3, 3, 7], pedersen.order)
    commitment = pedersen.commit(poly)

    point = random.randint(1, pedersen.order)

    proof, evaluation = pedersen.open(poly, point)

    assert pedersen.verify(commitment, proof, evaluation, point)
