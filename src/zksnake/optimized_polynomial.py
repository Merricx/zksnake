# pylint: disable=no-name-in-module
from flint import (
    fmpz_mod_poly,
    fmpz_mod_poly_ctx,
    fmpz_mod_ctx,
)
from .ecc import Curve


class PolynomialRing:
    def __init__(self, arg, p):
        """
        Initialize the polynomial with coefficients.

        coeffs: List of coefficients, where coeffs[i] is the coefficient of x^i.
        p: Prime number representing the finite field.
        """
        if isinstance(arg, fmpz_mod_poly):
            self.p = int(p)
            self.fmpz_p = fmpz_mod_ctx(self.p)
            self.poly = arg
        elif isinstance(arg, list):
            self.p = int(p)
            self.fmpz_p = fmpz_mod_ctx(self.p)
            self.poly = fmpz_mod_poly_ctx(self.fmpz_p)(arg)

    def coeffs(self):
        """Return the list of coefficents of the polynomial."""
        coeffs = self.poly.coeffs() or [0]
        return [int(x) for x in coeffs]

    def degree(self):
        """Return the degree of the polynomial."""
        return len(self.coeffs()) - 1

    def leading_coefficient(self):
        """Return the leading coefficient"""
        return self.poly.coeffs()

    def is_zero(self):
        """Return the boolean whether the polynomial is equal to zero"""
        return self.poly.is_zero()

    def __bool__(self):
        return not self.is_zero()

    def __str__(self):
        """Return the string representation of the polynomial."""
        return str(self.poly)

    def __repr__(self):
        return self.__str__()

    def __add__(self, other):
        return PolynomialRing(self.poly + other.poly, self.p)

    def __radd__(self, other):
        return self.__add__(other)

    def __neg__(self):
        """Negate polynomial coefficients"""
        return PolynomialRing(-self.poly, self.p)

    def __sub__(self, other):
        return PolynomialRing(self.poly - other.poly, self.p)

    def __rsub__(self, other):
        return self.__sub__(other)

    def __mul_by_polynomial(self, other):
        res = self.poly * other.poly
        if not res:
            return PolynomialRing([0], self.p)
        return PolynomialRing(res, self.p)

    def __mul_by_constant(self, c):
        """Multiply polynomial by constant"""
        return PolynomialRing(self.poly * c, self.p)

    def __mul__(self, other):
        if isinstance(other, PolynomialRing):
            return self.__mul_by_polynomial(other)
        elif isinstance(other, int):
            return self.__mul_by_constant(other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        """
        Divide two polynomials.
        Return quotient and remainder
        """
        return PolynomialRing(self.poly / other.poly, self.p), PolynomialRing(
            [0], self.p
        )

    def __eval(self, point: int) -> int:
        """Evaluate the polynomial at point"""
        return int(self.poly(point))

    def __eval_with_ecc(self, curves: list[Curve]) -> Curve:
        """Evaluate the polynomial over Elliptic Curve points"""

        result = [point * int(coeff) for point, coeff in zip(curves, self.coeffs())]
        total = result[0]
        for c in result[1:]:
            total += c

        return total

    def __call__(self, point: int | list[Curve]) -> int:
        if isinstance(point, int):
            return self.__eval(point)
        elif isinstance(point, list):
            return self.__eval_with_ecc(point)
        else:
            raise TypeError(f"Invalid argument: {point}")


def lagrange_polynomial(x, w, p):
    """Return Lagrange interpolating polynomial through points `(x, w)` over Fp"""
    M = len(x)
    p_ctx = fmpz_mod_ctx(p)
    P = fmpz_mod_poly_ctx(p_ctx)

    poly = P([0])
    for j in range(M):
        pt = P([w[j]])
        for k in range(M):
            if k == j:
                continue

            fac = x[j] - x[k]
            divided_poly = [-x[k], 1]
            res = []
            for c in divided_poly:
                res.append(c * pow(fac, -1, p) % p)

            pt *= P(res)
        poly += pt

    if not poly:
        poly = [0]

    return PolynomialRing(poly, p)
