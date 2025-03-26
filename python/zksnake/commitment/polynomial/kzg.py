from collections import defaultdict
from ...transcript import FiatShamirTranscript
from ...polynomial import Polynomial, lagrange_interpolation
from ...utils import get_random_int
from ...ecc import EllipticCurve
from .base import MultiOpeningQuery, PolynomialCommitmentScheme


class KZG(PolynomialCommitmentScheme):

    def __init__(self, max_degree, group):
        super().__init__(max_degree, group)
        self.E = EllipticCurve(self.group)
        self.order = self.E.order
        self.G1_tau = None
        self.G2_tau = None

    def setup(self):

        tau = get_random_int(self.order)
        power_of_tau = [pow(tau, i, self.order) for i in range(self.degree + 1)]

        self.G1_tau = self.E.batch_mul(self.E.G1(), power_of_tau)
        self.G2_tau = self.E.G2() * tau

    def commit(self, polynomial):

        assert self.G1_tau, "Trusted setup has not been run"

        commitment = self.E.multiexp(self.G1_tau, polynomial.coeffs())
        return commitment

    def open(self, polynomial, point, transcript=None):

        assert self.G1_tau, "Trusted setup has not been run"

        evaluation = polynomial(point)
        divisor_poly = Polynomial([-point % self.order, 1], self.order)
        quotient_poly, remainder = (polynomial - evaluation) / divisor_poly
        if not remainder.is_zero():
            raise ValueError("Given polynomial is not divided to zero")

        proof = self.E.multiexp(self.G1_tau, quotient_poly.coeffs())

        return proof, evaluation

    def verify(self, commitment, proof, opening, point, transcript=None):

        assert self.G1_tau, "Trusted setup has not been run"

        lhs = self.E.pairing(proof, self.G2_tau - self.E.G2() * point)
        rhs = self.E.pairing(commitment - self.E.G1() * opening, self.E.G2())

        return lhs == rhs

    def _group_evaluation(
        self, points_query: MultiOpeningQuery, x: int, is_verifier=False
    ):
        """
        Group polynomial (indexed by its commitment) into their evaluation points.

        Example:
        a(x), b(x), c(y), d(y) => {a, b} {c, d}
        a(x), b(x), c(x), c(y) => {a, b} {c}
        """

        group_map = defaultdict(set)
        for point, commitments in points_query.get_commitments():
            for commitment in commitments:
                group_map[commitment.to_hex()].add(point)

        result_map = defaultdict(set)
        for value, keys in group_map.items():
            result_map[frozenset(keys)].add(value)

        if not is_verifier:
            q_polys = []
            r_polys = []
            points_list = []
            for points, commitments in result_map.items():
                polys = [
                    points_query.to_polynomial(self.E.from_hex(commitment))
                    for commitment in commitments
                ]
                q = Polynomial([0], self.order)
                for i, poly in enumerate(polys):
                    q += pow(x, i, self.order) * poly

                xs = []
                ys = []
                for i, point in enumerate(points):
                    xs.append(point)
                    ys.append(q(point))

                r = lagrange_interpolation(xs, ys, self.order)

                q_polys.append(q)
                r_polys.append(r)
                points_list.append(list(points))

            return q_polys, r_polys, points_list
        else:
            q_commitments = []
            r_polys = []
            points_list = []
            for points, commitments in result_map.items():
                q = self.E.curve.PointG1.identity()
                for i, comm in enumerate(commitments):
                    q += pow(x, i, self.order) * self.E.from_hex(comm)

                xs = []
                ys = []

                for i, point in enumerate(points):
                    evaluations = [
                        pow(x, j, self.order)
                        * points_query.get_evaluation(self.E.from_hex(comm), point)
                        % self.order
                        for j, comm in enumerate(commitments)
                    ]
                    xs.append(point)
                    ys.append(sum(evaluations) % self.order)

                r = lagrange_interpolation(xs, ys, self.order)

                q_commitments.append(q)
                r_polys.append(r)
                points_list.append(list(points))

            return q_commitments, r_polys, points_list

    def multi_open(self, points_query, transcript=None):
        """
        Implementation based on Multipoint opening argument
        (https://zcash.github.io/halo2/design/proving-system/multipoint-opening.html)
        """

        assert self.G1_tau, "Trusted setup has not been run"

        transcript = transcript or FiatShamirTranscript(b"KZG", self.order)
        transcript.append(points_query.commitments)

        proof = []
        verifier_query = MultiOpeningQuery()
        for point, polys in points_query.get_polynomials():
            for poly in polys:
                evaluation = poly(point)
                comm = points_query.to_commitment(poly)
                verifier_query.verifier_query(comm, point, evaluation)

                transcript.append(evaluation)

        x1 = transcript.get_challenge_scalar()
        x2 = transcript.get_challenge_scalar()

        # group polynomials according to their evaluation points
        q_polys, r_polys, points_list = self._group_evaluation(points_query, x1)

        f_polys = []
        for i, points in enumerate(points_list):
            divisor = Polynomial([1], self.order)
            for point in points:
                divisor *= Polynomial([-point % self.order, 1], self.order)

            quotient, remainder = (q_polys[i] - r_polys[i]) / divisor
            assert remainder.is_zero()

            f_polys.append(quotient)

        f_poly = Polynomial([0], self.order)
        for i, poly in enumerate(f_polys):
            f_poly += pow(x2, i, self.order) * poly

        f_commitment = self.commit(f_poly)

        proof.append(f_commitment)
        transcript.append(f_commitment)
        x3 = transcript.get_challenge_scalar()

        q_polys_x3 = [q(x3) for q in q_polys]

        proof.extend(q_polys_x3)
        transcript.append(q_polys_x3)
        x4 = transcript.get_challenge_scalar()

        final_poly = f_poly
        for i, poly in enumerate(q_polys):
            final_poly += pow(x4, i + 1, self.order) * poly

        opening_proof, _ = self.open(final_poly, x3, transcript)
        proof.append(opening_proof)

        return proof, verifier_query

    def multi_verify(
        self, points_query: MultiOpeningQuery, proof: list, transcript=None
    ):

        assert self.G1_tau, "Trusted setup has not been run"
        assert len(proof) > 2, "Invalid proof"

        transcript = transcript or FiatShamirTranscript(b"KZG", self.order)
        transcript.append(points_query.commitments)

        for point, commitments in points_query.get_commitments():
            for commitment in commitments:
                evaluation = points_query.get_evaluation(commitment, point)
                transcript.append(evaluation)

        x1 = transcript.get_challenge_scalar()
        x2 = transcript.get_challenge_scalar()

        f_commitment = proof.pop(0)
        opening_proof = proof.pop()
        q_polys_x3 = proof

        transcript.append(f_commitment)
        x3 = transcript.get_challenge_scalar()
        transcript.append(q_polys_x3)
        x4 = transcript.get_challenge_scalar()

        q_commitments, r_polys, points_list = self._group_evaluation(
            points_query, x1, True
        )

        # construct f_poly(x3)
        f_poly_x3 = 0
        for i, points in enumerate(points_list):
            denominator = 1
            for point in points:
                denominator = denominator * (x3 - point) % self.order

            numerator = (q_polys_x3[i] - r_polys[i](x3)) % self.order

            f_poly_x3 += (
                pow(x2, i, self.order)
                * numerator
                * pow(denominator, -1, self.order)
                % self.order
            )

        f_poly_x3 %= self.order

        # construct final_commitment
        final_commitment = f_commitment
        for i, commitment in enumerate(q_commitments):
            final_commitment += pow(x4, i + 1, self.order) * commitment

        # construct final_poly(x3)
        q_x4 = 0
        for i, q in enumerate(q_polys_x3):
            q_x4 += pow(x4, i + 1, self.order) * q

        # final_poly(x3) = f_poly(x3) + x4^1 * q1(x3) + x4^2 * q2(x3) + ...
        final_poly_x3 = (f_poly_x3 + q_x4) % self.order

        # e(proof, g2 * tau - g2 * x3) == e(final_commitment - g1 * final_poly_eval, g2)
        return self.verify(final_commitment, opening_proof, final_poly_x3, x3)
