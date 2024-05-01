from enum import Enum
from typing import Union
from py_ecc import optimized_bls12_381, optimized_bn128
from py_ecc.fields.optimized_field_elements import FQ, FQ2
from py_ecc.fields import (
    optimized_bn128_FQ,
    optimized_bn128_FQ2,
    optimized_bls12_381_FQ,
    optimized_bls12_381_FQ2,
)


class CurveType(Enum):
    BN128 = optimized_bn128
    BN254 = optimized_bn128
    ALT_BN128 = optimized_bn128
    BLS12_381 = optimized_bls12_381


class CurveFQ(Enum):
    BN128 = optimized_bn128_FQ
    BN254 = optimized_bn128_FQ
    ALT_BN128 = optimized_bn128_FQ
    BLS12_381 = optimized_bls12_381_FQ


class CurveFQ2(Enum):
    BN128 = optimized_bn128_FQ2
    BN254 = optimized_bn128_FQ2
    ALT_BN128 = optimized_bn128_FQ2
    BLS12_381 = optimized_bls12_381_FQ2


class CurvePointSize(Enum):
    BN128 = 64
    BN254 = 64
    ALT_BN128 = 64
    BLS12_381 = 96


class EllipticCurve:
    def __init__(self, curve: str):
        self.name = curve
        self.curve = CurveType[curve].value.optimized_curve
        self.__pairing = CurveType[curve].value.optimized_pairing.pairing

    def G1(self):
        x, y, z = self.curve.G1
        return Curve(x, y, z, self.name, False)

    def G2(self):
        x, y, z = self.curve.G2
        return Curve(x, y, z, self.name, False)

    def G12(self):
        x, y, z = self.curve.G12
        return Curve(x, y, z, self.name, False)

    def pairing(self, a, b):
        return self.__pairing(a.point, b.point)

    def __call__(self, x, y, z=1):
        return Curve(x, y, z, self.name, True)


class Curve:
    def __init__(
        self,
        x: Union[int, tuple[int]],
        y: Union[int, tuple[int]],
        z: Union[int, tuple[int]],
        crv: str,
        verify=True,
    ):
        self.name = crv
        self.curve = CurveType[crv].value.optimized_curve
        fq = CurveFQ[crv].value
        fq2 = CurveFQ2[crv].value

        if (
            isinstance(x, (tuple, list))
            and isinstance(y, (tuple, list))
            and isinstance(z, (tuple, list))
        ):
            self.point = (fq2(x), fq2(y), fq2(z))
            if verify:
                assert self.curve.is_on_curve(
                    self.point, self.curve.b2
                ), "Invalid curve!"
        elif isinstance(x, int) and isinstance(y, int) and isinstance(z, int):
            self.point = (fq(x), fq(y), fq(z))
            if verify:
                assert self.curve.is_on_curve(
                    self.point, self.curve.b
                ), "Invalid curve!"
        else:
            # this point is not checked since it will come from internal arithmetic function
            self.point = (x, y, z)

    def __add__(self, other):
        if not isinstance(other, Curve):
            raise TypeError(
                f"Addition of {type(self)} with {type(other)} is not allowed"
            )

        result = self.curve.add(self.point, other.point)
        return Curve(result[0], result[1], result[2], self.name, False)

    def __radd__(self, other):
        return self.__add__(other)

    def __mul__(self, other):
        if not isinstance(other, int):
            raise TypeError(
                f"Multiplication of {type(self)} with {type(other)} is not allowed"
            )

        result = self.curve.multiply(self.point, other)
        return Curve(result[0], result[1], result[2], self.name, False)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __neg__(self):
        result = self.curve.neg(self.point)
        return Curve(result[0], result[1], result[2], self.name, False)

    def __str__(self) -> str:
        return f"{self.curve.normalize(self.point)}"

    def __repr__(self) -> str:
        return self.__str__()
    
    def is_zero(self) -> bool:
        return self.curve.is_inf(self.point)

    def hex(self) -> str:
        x, y = self.curve.normalize(self.point)
        point_size = CurvePointSize[self.name].value
        if isinstance(x, FQ) and isinstance(y, FQ):
            return hex(int(x))[2:].zfill(point_size) + hex(int(y))[2:].zfill(point_size)
        elif isinstance(x, FQ2) and isinstance(y, FQ2):
            x1, x2 = x.coeffs
            y1, y2 = y.coeffs

            return (
                hex(int(x1))[2:].zfill(point_size)
                + hex(int(x2))[2:].zfill(point_size)
                + hex(int(y1))[2:].zfill(point_size)
                + hex(int(y2))[2:].zfill(point_size)
            )
        else:
            raise TypeError(f"Unknown field element type: {type(x)} and {type(y)}")

def multiexp(g, e):
    """
    Perform Multi-Scalar-Multiplication (MSM)
    to compute sum of g[i] * e[i] where g is
    Elliptic Curve point and e is scalar
    from Polynomial coefficients
    """
