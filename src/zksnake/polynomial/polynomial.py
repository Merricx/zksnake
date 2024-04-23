from typing import Union
from ..ecc import Curve


class PolynomialRing:
    def __init__(self, coeffs, p):
        """
        Initialize the polynomial with coefficients.

        coeffs: List of coefficients, where coeffs[i] is the coefficient of x^i.
        p: Prime number representing the finite field.
        """
        self.__coeffs = [int(coeff) % p for coeff in coeffs]
        self.p = p

    def coeffs(self):
        """Return the list of coefficents of the polynomial."""
        return self.__coeffs

    def degree(self):
        """Return the degree of the polynomial."""
        return len(self.__coeffs) - 1

    def leading_coefficient(self):
        """Return the leading coefficient"""
        return self.__coeffs[-1]

    def is_zero(self):
        """Return the boolean whether the polynomial is equal to zero"""
        return all(c == 0 for c in self.__coeffs)

    def __bool__(self):
        return not self.is_zero()

    def __str__(self):
        """Return the string representation of the polynomial."""
        if self.is_zero():
            return "0"

        terms = []
        for i, coeff in enumerate(self.__coeffs):
            if coeff != 0:
                if i == 0:
                    terms.append(str(coeff))
                elif i == 1:
                    if coeff != 1:
                        terms.append(f"{coeff}*x")
                    else:
                        terms.append("x")
                else:
                    if coeff != 1:
                        terms.append(f"{coeff}*x^{i}")
                    else:
                        terms.append(f"x^{i}")

        return " + ".join(terms[::-1])

    def __repr__(self):
        return self.__str__()

    def __add__(self, other):
        if isinstance(other, int):
            coeffs = self.coeffs()[:]
            coeffs[0] += other

            return PolynomialRing(coeffs, self.p)

        max_degree = max(self.degree(), other.degree())
        result_coeffs = [
            (self.coeffs()[i] if i <= self.degree() else 0)
            + (other.coeffs()[i] if i <= other.degree() else 0)
            for i in range(max_degree + 1)
        ]
        return PolynomialRing(result_coeffs, self.p)

    def __radd__(self, other):
        return self.__add__(other)

    def __neg__(self):
        """Negate polynomial coefficients"""
        result_coeffs = [(-self.coeffs()[i]) % self.p for i in range(self.degree() + 1)]
        return PolynomialRing(result_coeffs, self.p)

    def __sub__(self, other):
        if isinstance(other, int):
            coeffs = self.coeffs()[:]
            coeffs[0] -= other

            return PolynomialRing(coeffs, self.p)

        max_degree = max(self.degree(), other.degree())
        result_coeffs = [
            (self.coeffs()[i] if i <= self.degree() else 0)
            - (other.coeffs()[i] if i <= other.degree() else 0)
            for i in range(max_degree + 1)
        ]
        return PolynomialRing(result_coeffs, self.p)

    def __rsub__(self, other):
        return self.__sub__(other)

    def __mul_by_polynomial(self, other):
        """Multiply two polynomials."""
        result_coeffs = [0] * (self.degree() + other.degree() + 1)
        for i in range(self.degree() + 1):
            for j in range(other.degree() + 1):
                result_coeffs[i + j] += self.coeffs()[i] * other.coeffs()[j]
                result_coeffs[i + j] %= self.p

        return PolynomialRing(result_coeffs, self.p)

    def __mul_by_constant(self, c):
        """Multiply polynomial by constant"""
        result_coeffs = []
        for coeff in self.coeffs():
            result_coeffs.append(c * coeff % self.p)

        return PolynomialRing(result_coeffs, self.p)

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
        if other.degree() == -1:
            raise ZeroDivisionError("Division by zero")
        if self.degree() < other.degree():
            return PolynomialRing([0], self.p), PolynomialRing([0], self.p)

        dividend = self.coeffs()[:]
        divisor = other.coeffs()[:]

        n = other.degree()
        quotient = [0] * (self.degree() - n + 1)

        for k in reversed(range(0, len(quotient))):
            quotient[k] = dividend[n + k] * pow(divisor[n], -1, self.p) % self.p
            for j in range(k, n + k):
                dividend[j] -= quotient[k] * divisor[j - k]

        remainder = dividend[:n]

        return PolynomialRing(quotient, self.p), PolynomialRing(remainder, self.p)

    def __eval(self, point: int) -> int:
        """Evaluate the polynomial at point"""
        return (
            sum([c * pow(point, i, self.p) for i, c in enumerate(self.coeffs())])
            % self.p
        )

    def __eval_with_ecc(self, curves: list[Curve]) -> Curve:
        """Evaluate the polynomial over Elliptic Curve points"""
        assert len(curves) == len(self.coeffs())
        result = [point * coeff for point, coeff in zip(curves, self.coeffs())]
        total = result[0]
        for c in result[1:]:
            total += c

        return total

    def __call__(self, point: Union[int, list[Curve]]) -> int:
        if isinstance(point, int):
            return self.__eval(point)
        elif isinstance(point, list):
            return self.__eval_with_ecc(point)
        else:
            raise TypeError(f"Invalid argument: {point}")


cached_lagrange_multipliers = {}


def lagrange_polynomial(x, w, p):
    """Return Lagrange interpolating polynomial through points `(x, w)` over Fp"""
    M = len(x)
    poly = PolynomialRing([0], p)
    for j in range(M):
        pt = PolynomialRing([w[j]], p)
        res_product = PolynomialRing([1], p)

        if j in cached_lagrange_multipliers:
            res_product = cached_lagrange_multipliers[j]
        else:
            for k in range(M):
                if k == j:
                    continue

                fac = x[j] - x[k]
                divided_poly = [-x[k], 1]
                res = []
                for c in divided_poly:
                    res.append(c * pow(fac, -1, p) % p)

                res_product *= PolynomialRing(res, p)

            cached_lagrange_multipliers[j] = res_product

        poly += pt * res_product

    return poly


def vanishing_polynomial(degree: int, p: int):
    """Generate polynomial `T = (x - 1) * (x - 2) * (x - 3) ... (x - n)`"""
    poly = PolynomialRing([1], p)
    for i in range(1, degree + 1):
        poly *= PolynomialRing([-i, 1], p)

    return poly


def clear_cache():
    """Clear all lagrange multiplier cache"""
    global cached_lagrange_multipliers  # pylint: disable=global-statement
    cached_lagrange_multipliers = {}
