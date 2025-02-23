from enum import Enum

from zksnake._algebra import ec_bn254, ec_bls12_381  # pylint: disable=no-name-in-module
from .constant import (
    BLS12_381_MODULUS,
    BLS12_381_SCALAR_FIELD,
    BN254_MODULUS,
    BN254_SCALAR_FIELD,
)


class CurveType(Enum):
    BN128 = ec_bn254
    BN254 = ec_bn254
    ALT_BN128 = ec_bn254
    BLS12_381 = ec_bls12_381


class CurveField(Enum):
    BN128 = BN254_MODULUS
    BN254 = BN254_MODULUS
    ALT_BN128 = BN254_MODULUS
    BLS12_381 = BLS12_381_MODULUS


class CurveOrder(Enum):
    BN128 = BN254_SCALAR_FIELD
    BN254 = BN254_SCALAR_FIELD
    ALT_BN128 = BN254_SCALAR_FIELD
    BLS12_381 = BLS12_381_SCALAR_FIELD


class CurveScalarSize(Enum):
    BN128 = 32
    BN254 = 32
    ALT_BN128 = 32
    BLS12_381 = 32


class CurvePointSize(Enum):
    BN128 = 32
    BN254 = 32
    ALT_BN128 = 32
    BLS12_381 = 48


def ispointG1(x):
    return isinstance(x, (ec_bn254.PointG1, ec_bls12_381.PointG1))


def ispointG2(x):
    return isinstance(x, (ec_bn254.PointG2, ec_bls12_381.PointG2))


class EllipticCurve:
    def __init__(self, curve: str):
        self.name = curve
        self.curve = CurveType[curve].value
        self.order = CurveOrder[curve].value
        self.field_modulus = CurveField[curve].value

    def G1(self):
        """
        Return generator G1 of the curve
        """
        return self.curve.g1()

    def G2(self):
        """
        Return generator G2 of the curve
        """
        return self.curve.g2()

    def pairing(self, a, b):
        """
        Compute pairing, that is `e(a, b)`, where `a in G1` and `b in G2`
        """
        return self.curve.pairing(a, b)

    def multi_pairing(self, a: list, b: list):
        """
        Perform pairing of e(a[i], b[i]) in batch
        and compute its product
        """
        assert len(a) == len(b), "Length of a and b must be equal"
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
            raise TypeError(f"Invalid curve type: {g[0]}")

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
            raise TypeError(f"Invalid curve type: {type(g[0])}")

    def from_hex(self, hexstring: str):
        """
        Construct Elliptic curve point from serialized hexstring
        """
        b = bytes.fromhex(hexstring)
        n = CurvePointSize[self.name].value * 2

        if len(hexstring) == n:
            return self.curve.PointG1.from_bytes(b)
        elif len(hexstring) == n * 2:
            return self.curve.PointG2.from_bytes(b)
        else:
            raise ValueError(
                f"Hexstring size of {n} or {n*2} expected, got {len(hexstring)}"
            )

    def __call__(self, x, y):

        if isinstance(x, (tuple, list)) and isinstance(y, (tuple, list)):
            return self.curve.PointG2(x[0], x[1], y[0], y[1])
        else:
            return self.curve.PointG1(x, y)
