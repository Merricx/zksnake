import random
from zksnake.commitment.polynomial import KZG, Pedersen
from zksnake.polynomial import Polynomial


def test_kzg():

    kzg = KZG(4, "BN254")
    kzg.setup()

    poly = Polynomial([1, 3, 3, 7], kzg.order)
    commitment = kzg.commit(poly)

    point = random.randint(1, kzg.order)

    proof, evaluation = kzg.open(poly, point)

    assert kzg.verify(commitment, proof, evaluation, point)


def test_pedersen():

    pedersen = Pedersen(4, "BN254")
    pedersen.setup()

    poly = Polynomial([1, 3, 3, 7], pedersen.order)
    commitment = pedersen.commit(poly)

    point = random.randint(1, pedersen.order)

    proof, evaluation = pedersen.open(poly, point)

    assert pedersen.verify(commitment, proof, evaluation, point)
