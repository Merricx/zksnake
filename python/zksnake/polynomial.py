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
    poly = POLY_OBJECT[p]
    return poly.PolynomialRing(coeffs)


def fft(domain, p):
    poly = POLY_OBJECT[p]
    return poly.fft(domain)


def ifft(domain, p):
    poly = POLY_OBJECT[p]
    return poly.ifft(domain)


def evaluate_vanishing_polynomial(domain, tau, p):
    poly = POLY_OBJECT[p]
    return poly.evaluate_vanishing_polynomial(domain, tau)


def evaluate_lagrange_coefficients(domain, tau, p):
    poly = POLY_OBJECT[p]
    return poly.evaluate_lagrange_coefficients(domain, tau)
