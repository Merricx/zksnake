# pylint: disable=no-name-in-module
from zksnake._algebra import (
    polynomial_bn254,
    polynomial_bls12_381,
)


POLY_OBJECT = {
    21888242871839275222246405745257275088548364400416034343698204186575808495617: polynomial_bn254,
    52435875175126190479447740508185965837690552500527637822603658699938581184513: polynomial_bls12_381,
}


def PolynomialRing(coeffs, p):
    """
    Constructs a new polynomial from a list of coefficients over finite field `p`,
    such that `... coeffs[2]*x^2 + coeffs[1]*x + coeffs[0]`.
    """
    poly = POLY_OBJECT[p]
    return poly.PolynomialRing(coeffs)


def fft(coeffs, p):
    """
    Perform FFT from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    return poly.fft(coeffs)


def coset_fft(coeffs, p):
    """
    Perform FFT over Coset from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    return poly.coset_fft(coeffs)


def ifft(coeffs, p):
    """
    Perform inverse FFT from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    return poly.ifft(coeffs)


def coset_ifft(coeffs, p):
    """
    Perform inverse FFT over Coset from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    return poly.coset_ifft(coeffs)


def mul_over_evaluation_domain(a, b, p):
    poly = POLY_OBJECT[p]
    return poly.mul_over_evaluation_domain(a, b)


def evaluate_vanishing_polynomial(domain, tau, p):
    poly = POLY_OBJECT[p]
    return poly.evaluate_vanishing_polynomial(domain, tau)


def evaluate_lagrange_coefficients(domain, tau, p):
    poly = POLY_OBJECT[p]
    return poly.evaluate_lagrange_coefficients(domain, tau)

def lagrange_polynomial(x, y, p):
    """
    Naive implementation of Lagrange interpolation from given points `(x_i, y_i)`.
    For very big points, use iFFT instead.
    """
    M = len(x)
    poly = PolynomialRing([0], p)
    for j in range(M):
        pt = PolynomialRing([y[j]], p)
        for k in range(M):
            if k == j:
                continue
            fac = x[j] - x[k]
            divided_poly = [-x[k], 1]
            res = []
            for c in divided_poly:
                res.append(c * pow(fac, -1, p) % p)
            pt *= PolynomialRing(res, p)
        poly += pt
    return poly