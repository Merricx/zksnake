import pytest
from zksnake.polynomial import *

def test_univariate_polynomial():

    for p in (BN254_SCALAR_FIELD, BLS12_381_SCALAR_FIELD):
    
        a = PolynomialRing([1,2,3], p)
        b = PolynomialRing([2,3,4], p)

        assert a + b == PolynomialRing([x+y for x,y in zip(a.coeffs(), b.coeffs())], p)
        assert b - a == PolynomialRing([x-y % p for x,y in zip(b.coeffs(), a.coeffs())], p)
        assert a*b == PolynomialRing([2,7,16,17,12], p)
        assert (a * b / a)[0] == b
        assert (a * b / b)[0] == a

        assert a + 5 == PolynomialRing([6,2,3], p)
        assert a - 1 == PolynomialRing([0,2,3], p)
        assert a * 2 == PolynomialRing([2,4,6], p)

        assert a(2) == (1 + 2*2 + 2**2*3) % p
        assert b(2) == (2 + 2*3 + 2**2*4) % p

def test_multivariate_polynomial():

    for p in (BN254_SCALAR_FIELD, BLS12_381_SCALAR_FIELD):
        # 3x + 2y
        a = PolynomialRing({(1,0):3, (0,1):2}, p)
        # 5x + 7y
        b = PolynomialRing({(1,0):5, (0,1):7}, p)

        assert a + b == PolynomialRing({(0, 1): 9, (1, 0): 8}, p)
        assert b - a == PolynomialRing({(0, 1): 5, (1, 0): 2}, p)
        assert a * b == PolynomialRing({(0, 2): 14, (1, 1): 31, (2, 0): 15}, p)

        assert a + 5 == PolynomialRing({(1,0):3, (0,1):2, (0,0): 5}, p)
        assert a - 1 == PolynomialRing({(1,0):3, (0,1):2, (0,0): p-1}, p)
        assert a * 2 == PolynomialRing({(1,0):6, (0,1):4}, p)

        assert a([5,10]) == (3*5 + 2*10) % p
        assert b([5,10]) == (5*5 + 7*10) % p