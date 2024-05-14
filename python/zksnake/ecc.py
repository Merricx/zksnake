from enum import Enum

from zksnake._algebra import ec_bn254, ec_bls12_381  # pylint: disable=no-name-in-module


class CurveType(Enum):
    BN128 = ec_bn254
    BN254 = ec_bn254
    ALT_BN128 = ec_bn254
    BLS12_381 = ec_bls12_381


Q_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Q_BLS12_381 = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)


class CurveOrder(Enum):
    BN128 = Q_BN254
    BN254 = Q_BN254
    ALT_BN128 = Q_BN254
    BLS12_381 = Q_BLS12_381


class CurvePointSize(Enum):
    BN128 = 64
    BN254 = 64
    ALT_BN128 = 64
    BLS12_381 = 96


class EllipticCurve:
    def __init__(self, curve: str):
        self.name = curve
        self.curve = CurveType[curve].value
        self.order = CurveOrder[curve].value

    def G1(self):
        return self.curve.g1()

    def G2(self):
        return self.curve.g2()

    def pairing(self, a, b):
        return self.curve.pairing(a, b)

    def multi_pairing(self, a, b):
        return self.curve.multi_pairing(a, b)

    def batch_mul(self, g, s):
        """
        Perform EC multiplication in parallel batch
        where g is Elliptic Curve point(s) and s is scalars
        """

        if not isinstance(g, list):
            g = [g] * len(s)

        if len(g) == 0:
            return []

        if isinstance(g[0], self.curve.PointG1):
            return self.curve.batch_multi_scalar_g1(g, s)
        elif isinstance(g[0], self.curve.PointG2):
            return self.curve.batch_multi_scalar_g2(g, s)
        else:
            raise ValueError("Invalid type")

    def multiexp(self, g, s):
        """
        Perform Multi-Scalar-Multiplication (MSM)
        to compute sum of g[i] * s[i] where g is
        Elliptic Curve point and s is scalar
        """
        assert len(g) > 0

        if len(s) == 0:
            return g[0] * 0

        if len(s) < len(g):
            g = g[: len(s)]

        if isinstance(g[0], self.curve.PointG1):
            return self.curve.multiscalar_mul_g1(g, s)
        elif isinstance(g[0], self.curve.PointG2):
            return self.curve.multiscalar_mul_g2(g, s)
        else:
            raise ValueError("Invalid type")

    def __call__(self, x, y, z=1):

        if isinstance(x, (tuple, list)) and isinstance(y, (tuple, list)):
            return self.curve.PointG2(x[0], x[1], y[0], y[1])
        else:
            return self.curve.PointG1(x, y)
