from ...utils import get_random_int
from ...transcript import FiatShamirTranscript, hash_to_curve
from ...ecc import EllipticCurve

from .base import PolynomialCommitmentScheme


class Pedersen(PolynomialCommitmentScheme):

    def __init__(self, max_degree, curve):
        super().__init__(max_degree, curve)
        self.E = EllipticCurve(self.group)
        self.order = self.E.order
        self.G = None
        self.H = None
        self.blindings = None

    def setup(self, seed=b"Pedersen"):
        self.G = hash_to_curve(seed, b'G', self.group)
        self.H = hash_to_curve(seed, b'H', self.group)
        self.blindings = [get_random_int(self.order)
                          for _ in range(self.degree + 1)]

    def commit(self, polynomial):
        assert polynomial.degree() <= self.degree

        cs = polynomial.coeffs() + \
            [0 for _ in range(self.degree - polynomial.degree())]

        comms = []
        for i in range(self.degree+1):
            comms.append(cs[i] * self.G + self.blindings[i] * self.H)

        return comms

    def open(self, polynomial, point, transcript=None):

        opening = polynomial(point)
        proof = 0
        for i, gamma in enumerate(self.blindings):
            proof += gamma * pow(point, i, self.order)

        return proof % self.order, opening
    
    def multi_open(self, polynomials, commitments, transcript=None):
        return super().multi_open(polynomials, commitments, transcript)

    def verify(self, commitment, proof, opening, point, transcript=None):

        scalars = [pow(point, i, self.order) for i in range(self.degree + 1)]
        lhs = self.E.multiexp(commitment, scalars)

        rhs = opening * self.G + proof * self.H

        return lhs == rhs
