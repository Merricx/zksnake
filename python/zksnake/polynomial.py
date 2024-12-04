# pylint: disable=no-name-in-module
from zksnake._algebra import (
    polynomial_bn254,
    polynomial_bls12_381,
)
from .utils import is_power_of_two, next_power_of_two
from .constant import BN254_SCALAR_FIELD, BLS12_381_SCALAR_FIELD

POLY_OBJECT = {
    BN254_SCALAR_FIELD: polynomial_bn254,
    BLS12_381_SCALAR_FIELD: polynomial_bls12_381,
}


def PolynomialRing(coeffs, p, domain_size=None):
    """
    Constructs a new polynomial from a list of coefficients over finite field `p`,
    such that `... coeffs[2]*x^2 + coeffs[1]*x + coeffs[0]`.
    """
    poly = POLY_OBJECT[p]
    if not domain_size:
        domain_size = len(coeffs)
    return poly.PolynomialRing(coeffs, domain_size)

def get_nth_root_of_unity(domain, i, p) -> int:
    """
    get `i`th root of unity over evaluation domain of size `domain`
    """
    if i == 0:
        return 1
    poly = POLY_OBJECT[p]
    return poly.get_nth_root_of_unity(domain, i)

def get_all_root_of_unity(domain, p) -> list:
    """
    get all elements of evaluation domain of size `domain`
    """
    poly = POLY_OBJECT[p]
    return poly.get_all_root_of_unity(domain)

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


def ifft(coeffs, p, size=None):
    """
    Perform inverse FFT from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    size = size or len(coeffs)
    return poly.ifft(coeffs, size)


def coset_ifft(coeffs, p, size=None):
    """
    Perform inverse FFT over Coset from given `coeffs`
    """
    poly = POLY_OBJECT[p]
    size = size or len(coeffs)
    return poly.coset_ifft(coeffs, size)

def mul_over_fft(domain, a, b, p, return_poly=True):
    a_degree = a.degree()
    b_degree = b.degree()

    pad_a = []
    pad_b = []
    if a_degree != b_degree:
        max_pad = max(a_degree, b_degree)
        length = next_power_of_two(max_pad)
        if a_degree > b_degree:
            pad_a = [0]*length
            pad_b = [0]*(a_degree+length-b_degree)
        else:
            pad_b = [0]*length
            pad_a = [0]*(b_degree+length-a_degree)
    else:
        pad_a = [0]*next_power_of_two(a_degree)
        pad_b = [0]*next_power_of_two(a_degree)
    
    a_fft = fft(a.coeffs()+pad_a, p)
    b_fft = fft(b.coeffs()+pad_b, p)
    ab_fft = mul_over_evaluation_domain(domain, a_fft, b_fft, p)
    
    if return_poly:
        return PolynomialRing(ifft(ab_fft, p), p, domain)
    
    return ab_fft

def mul_over_evaluation_domain(domain, a, b, p):
    poly = POLY_OBJECT[p]
    return poly.mul_over_evaluation_domain(domain, a, b)


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