from typing import Dict, Sequence, Tuple, Union

# pylint: disable=no-name-in-module
from zksnake._algebra import (
    polynomial_bn254,
    polynomial_bls12_381,
)
from .utils import next_power_of_two
from .constant import BN254_SCALAR_FIELD, BLS12_381_SCALAR_FIELD

POLY_OBJECT = {
    BN254_SCALAR_FIELD: polynomial_bn254,
    BLS12_381_SCALAR_FIELD: polynomial_bls12_381,
}


def Polynomial(
    coeffs: Union[Sequence[int], Dict[Tuple[int], int]], p, domain_size=None
):
    """
    Construct univariate or multivariate polynomial
    depending if `coeffs` is `list` or `dict`, respectively.

    ## Univariate Polynomial
    Constructs a new univariate polynomial from a list of coefficients over finite field `p`,
    such that `... coeffs[2]*x^2 + coeffs[1]*x + coeffs[0]`.

    ## Multivariate Polynomial
    Constructs a new multivariate polynomial that is
    represented as a dictionary, where:
        - Keys are tuples of non-negative integers representing the exponents
          of each variable in a term (e.g., `(2, 1, 0)` for `x^2 * y^1 * z^0`).
        - Values are the coefficients of the corresponding terms (e.g., `3` for `3 * x^2 * y`).
    """
    poly = POLY_OBJECT[p]
    if not domain_size:
        domain_size = len(coeffs)

    num_vars = 1
    if isinstance(coeffs, list):
        coeff_terms = []
        for c in coeffs:
            coeff_terms.append((c, [(0, 0)]))
    elif isinstance(coeffs, dict):
        coeff_terms = []
        num_vars = len(next(iter(coeffs)))

        for terms, coeff in coeffs.items():
            sparse_terms = []
            for v, power in enumerate(terms):
                if power != 0:
                    sparse_terms.append((v, power))

            coeff_terms.append((coeff, sparse_terms))
    else:
        raise TypeError("Coefficients must be in list or dict")

    return poly.Polynomial(num_vars, coeff_terms, domain_size)


def MultilinearPolynomial(num_vars: int, sparse_evaluations: Tuple[int, int], p: int):
    """
    Constructs Sparse Multilinear Polynomial from tuple of evaluations `(index, eval)`
    of non-zero evaluation over boolean hypercube
    """
    poly = POLY_OBJECT[p]
    if num_vars == 0:
        return poly.MultilinearPolynomial.zero()
    return poly.MultilinearPolynomial(num_vars, sparse_evaluations)


def get_evaluation_point(domain, i, p) -> int:
    """
    get `i`th element over evaluation domain of size `domain`
    """
    if i == 0:
        return 1
    poly = POLY_OBJECT[p]
    return poly.get_evaluation_point(domain, i)


def get_all_evaluation_points(domain, p) -> list:
    """
    get all elements of evaluation domain of size `domain`
    """
    poly = POLY_OBJECT[p]
    return poly.get_all_evaluation_points(domain)


def fft(coeffs, p, size=None):
    """
    Perform FFT from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    size = size or len(coeffs)
    return poly.fft(coeffs, size)


def coset_fft(coeffs, p, size=None):
    """
    Perform FFT over Coset from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    size = size or len(coeffs)
    return poly.coset_fft(coeffs, size)


def ifft(evals, p, size=None):
    """
    Perform inverse FFT from given `evals`
    """
    poly = POLY_OBJECT[p]
    size = size or len(evals)
    return poly.ifft(evals, size)


def coset_ifft(coeffs, p, size=None):
    """
    Perform inverse FFT over Coset from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    size = size or len(coeffs)
    return poly.coset_ifft(coeffs, size)


def _pad_coeffs(a, b):
    a_degree = len(a) - 1
    b_degree = len(b) - 1

    pad_a = []
    pad_b = []
    if a_degree != b_degree:
        max_pad = max(a_degree, b_degree)
        length = next_power_of_two(max_pad)
        if a_degree > b_degree:
            pad_a = [0] * length
            pad_b = [0] * (a_degree + length - b_degree)
        else:
            pad_b = [0] * length
            pad_a = [0] * (b_degree + length - a_degree)
    else:
        pad_a = [0] * next_power_of_two(a_degree)
        pad_b = [0] * next_power_of_two(a_degree)

    a = a + pad_a
    b = b + pad_b

    return a, b


def mul_over_fft(domain, a, b, p, return_poly=True):
    """
    Multiply two polynomials (in coefficient form) `a` and `b` over FFT domain.
    If `return_poly` is `False`, return the evaluation form instead of polynomial.
    """
    a, b = _pad_coeffs(a.coeffs(), b.coeffs())

    a_fft = fft(a, p)
    b_fft = fft(b, p)
    ab_fft = mul_over_evaluation_domain(len(a_fft), a_fft, b_fft, p)

    if return_poly:
        return Polynomial(ifft(ab_fft, p), p, domain)

    return ab_fft


def add_over_evaluation_domain(domain, evals: list, p):
    """
    Add multiple polynomials in evaluation form.
    """
    poly = POLY_OBJECT[p]
    result = evals[0]
    for adder in evals[1:]:
        result = poly.add_over_evaluation_domain(domain, result, adder)

    return result


def mul_over_evaluation_domain(domain, a, b, p):
    """
    Multiply two polynomials in evaluation form.
    """
    poly = POLY_OBJECT[p]
    return poly.mul_over_evaluation_domain(domain, a, b)


def evaluate_vanishing_polynomial(domain, x, p):
    """
    Evaluate vanishing polynomial defined by this domain at the point `x`.
    """
    poly = POLY_OBJECT[p]
    return poly.evaluate_vanishing_polynomial(domain, x)


def evaluate_lagrange_coefficients(domain, x, p):
    """
    Evaluate all the lagrange polynomials defined by this domain at the point `x`.
    """
    poly = POLY_OBJECT[p]
    return poly.evaluate_lagrange_coefficients(domain, x)


def barycentric_eval(domain, sparse_eval: dict, x, p):
    """
    Evaluate a polynomial at a given point x using sparse evaluation form.
    """
    omega = get_evaluation_point(domain, 1, p)

    sum_i = 0
    for i in sparse_eval:
        w_i = pow(omega, i, p)
        sum_i += (sparse_eval[i] * w_i) * pow(x - w_i, -1, p)

    return (pow(x, domain, p) - 1) * pow(domain, -1, p) * sum_i % p


def lagrange_interpolation(x, y, p):
    """
    Naive implementation of Lagrange interpolation from given points `(x_i, y_i)`.
    For very large points, use iFFT instead.
    """
    M = len(x)
    poly = Polynomial([0], p)
    for j in range(M):
        pt = Polynomial([y[j]], p)
        for k in range(M):
            if k == j:
                continue
            fac = x[j] - x[k]
            divided_poly = [-x[k], 1]
            res = []
            for c in divided_poly:
                res.append(c * pow(fac, -1, p) % p)
            pt *= Polynomial(res, p)
        poly += pt
    return poly
