from enum import Enum
from py_ecc import optimized_bls12_381, optimized_bn128

class CurveType(Enum):
    BN128 = optimized_bn128
    BN254 = optimized_bn128
    ALT_BN128 = optimized_bn128
    BLS12_381 = optimized_bls12_381

class EllipticCurve:
    def __init__(self, curve: str):
        self.curve = CurveType[curve].value.optimized_curve
        self.__pairing = CurveType[curve].value.optimized_pairing.pairing

    def G1(self):
        x, y, z = self.curve.G1
        return Curve(x, y, z, self.curve)

    def G2(self):
        x, y, z = self.curve.G2
        return Curve(x, y, z, self.curve)
        
    def G12(self):
        x, y, z = self.curve.G12
        return Curve(x, y, z, self.curve)
    
    def pairing(self, a, b):
        return self.__pairing(a.point, b.point)

    def __call__(self, x, y, z=1):
        return Curve(x, y, z, self.curve)


class Curve:
    def __init__(self, x, y, z, crv):
        self.curve = crv
        self.point = (x, y, z)

    def __add__(self, other):
        if not isinstance(other, Curve):
            raise TypeError(f"Addition of {type(self)} with {type(other)} is not allowed")
        
        result = self.curve.add(self.point, other.point)
        return Curve(result[0], result[1], result[2], self.curve)
    
    def __radd__(self, other):
        return self.__add__(other)
    
    def __mul__(self, other):
        if not isinstance(other, int):
            raise TypeError(f"Multiplication of {type(self)} with {type(other)} is not allowed")
        
        result = self.curve.multiply(self.point, other)
        return Curve(result[0], result[1], result[2], self.curve)
    
    def __rmul__(self, other):
        return self.__mul__(other)
    
    def __neg__(self):
        result = self.curve.neg(self.point)
        return Curve(result[0], result[1], result[2], self.curve)
    
    def __str__(self) -> str:
        return f"{self.curve.normalize(self.point)}"
    
    def __repr__(self) -> str:
        return self.__str__()