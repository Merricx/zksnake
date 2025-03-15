from zksnake.transcript import FiatShamirTranscript
from ...polynomial import PolynomialRing
from ...utils import get_random_int
from ...ecc import EllipticCurve
from .base import PolynomialCommitmentScheme


class KZG(PolynomialCommitmentScheme):

    def __init__(self, max_degree, group):
        super().__init__(max_degree, group)
        self.E = EllipticCurve(self.group)
        self.order = self.E.order
        self.G1_tau = None
        self.G2_tau = None

    def setup(self):

        tau = get_random_int(self.order)
        power_of_tau = [pow(tau, i, self.order) for i in range(self.degree+1)]

        self.G1_tau = self.E.batch_mul(self.E.G1(), power_of_tau)
        self.G2_tau = self.E.G2() * tau

    def _kate_division(self, polynomial, point, evaluation):
        """
        Q(X) = (P(X) - P(point)) / (X - point)
        """

        divisor_poly = PolynomialRing([-point % self.order, 1], self.order)
        quotient_poly, remainder = (polynomial - evaluation) / divisor_poly
        if not remainder.is_zero():
            raise ValueError("Given polynomial is not divided to zero")

        return quotient_poly

    def commit(self, polynomial):

        assert self.G1_tau, "Trusted setup has not been run"

        commitment = self.E.multiexp(self.G1_tau, polynomial.coeffs())
        return commitment

    def open(self, polynomial, point, transcript=None):

        assert self.G1_tau, "Trusted setup has not been run"

        evaluation = polynomial(point)
        quotient_poly = self._kate_division(polynomial, point, evaluation)
        proof = self.E.multiexp(self.G1_tau, quotient_poly.coeffs())

        return proof, evaluation

    def verify(self, commitment, proof, opening, point, transcript=None):

        assert self.G1_tau, "Trusted setup has not been run"

        lhs = self.E.pairing(proof, self.G2_tau - self.E.G2() * point)
        rhs = self.E.pairing(commitment - self.E.G1() * opening, self.E.G2())

        return lhs == rhs

    def multi_open(self, points_query, commitments, transcript=None):
        """
        Implementation based from SHPLONK (https://eprint.iacr.org/2020/081.pdf, section 4.1)
        """
        
        assert self.G1_tau, "Trusted setup has not been run"

        transcript = transcript or FiatShamirTranscript(b'KZG', self.order)
        transcript.append(commitments)

        evaluations = []
        for point, polys in points_query.items():
            for poly in polys:
                evaluation = poly(point)
                evaluations.append(evaluation)
                transcript.append(evaluation)

        x1 = transcript.get_challenge_scalar()
        x2 = transcript.get_challenge_scalar()

        # group polynomials according to their evaluation points
        q_polys = []
        for _, polys in points_query.items():
            q = PolynomialRing([0], self.order)
            for i, poly in enumerate(polys):
                q += pow(x1, i, self.order) * poly

            q_polys.append(q)