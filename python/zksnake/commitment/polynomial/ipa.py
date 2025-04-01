import math
from collections import defaultdict

from ...polynomial import Polynomial, lagrange_interpolation
from ...ecc import EllipticCurve
from ...transcript import hash_to_curve, FiatShamirTranscript
from ...utils import inner_product, next_power_of_two, get_random_int
from .base import MultiOpeningQuery, PolynomialCommitmentScheme


class IPA(PolynomialCommitmentScheme):
    """
    Protocol based on BCMS20 (https://eprint.iacr.org/2020/499.pdf, Appendix A.),
    with the notation follows https://www.zkdocs.com/docs/zkdocs/commitments/ipa-pcs/
    """

    def __init__(self, max_degree, group):
        super().__init__(max_degree, group)
        self.name = "IPA-PCS"
        self.E = EllipticCurve(self.group)
        self.order = self.E.order
        self.n = 0
        self.G = []
        self.H = None

    def __split_half(self, data: list):
        if len(data) > 2:
            mid_index = len(data) // 2
            return data[:mid_index], data[mid_index:]
        elif len(data) == 2:
            return [data[0]], [data[1]]
        else:
            return [data[0]], []

    def setup(self, seed=None):
        seed = seed or self.name.encode()
        self.n = next_power_of_two(self.degree)
        self.G = hash_to_curve(seed, b"G", self.E.name, self.n)
        self.H = hash_to_curve(seed, b"H", self.E.name, 1)

        self.is_setup = True

    def zero_commitment(self):
        return self.E.curve.PointG1.identity()

    # pylint: disable-next=arguments-differ
    def commit(self, polynomial, blinding: int):

        assert self.is_setup, "Trusted setup has not been run"
        assert (
            polynomial.degree() < self.n
        ), "Polynomial exceeded maximum allowed degree"

        coeff = polynomial.coeffs() + [
            0 for _ in range(self.n - polynomial.degree() - 1)
        ]

        return self.E.multiexp(self.G + [self.H], coeff + [blinding])

    # pylint: disable-next=arguments-differ
    def open(
        self,
        polynomial,
        point,
        commitment,
        blinding,
        transcript=None,
    ):
        assert self.is_setup, "Trusted setup has not been run"

        a = polynomial.coeffs() + [0 for _ in range(self.n - polynomial.degree())]
        b = [pow(point, i, self.order) for i in range(self.n)]
        evaluation = polynomial(point)

        transcript = transcript or FiatShamirTranscript(self.name.encode(), self.order)
        transcript.append(self.G)
        transcript.append(self.H)
        transcript.append(point)
        transcript.append(evaluation)
        transcript.append(commitment)

        poly_r = Polynomial(
            [get_random_int(self.order - 1) for _ in range(self.n)], self.order
        )
        f_bar = poly_r - poly_r(point)
        a_bar = f_bar.coeffs()

        t_bar = get_random_int(self.order - 1)
        commitment_bar = self.E.multiexp(self.G + [self.H], a_bar + [t_bar])

        transcript.append(commitment_bar)
        alpha = transcript.get_challenge_scalar()

        c = [(x + alpha * y) % self.order for x, y in zip(a, a_bar)]
        t_prime = blinding + alpha * t_bar

        commitment_prime = self.E.multiexp(self.G, c)
        transcript.append(commitment_prime)
        h_prime = hash_to_curve(transcript.get_challenge(), b"U", self.E.name, 1)

        commitment_0 = commitment_prime + evaluation * h_prime
        transcript.append(commitment_0)

        L_list = []
        R_list = []
        u_list = []

        n = self.n
        G = self.G

        while n != 1:
            n //= 2

            c_low, c_hi = self.__split_half(c)
            b_low, b_hi = self.__split_half(b)
            G_low, G_hi = self.__split_half(G)

            L = (
                self.E.multiexp(G_low, c_hi)
                + inner_product(c_hi, b_low, self.order) * h_prime
            )

            R = (
                self.E.multiexp(G_hi, c_low)
                + inner_product(c_low, b_hi, self.order) * h_prime
            )

            L_list.append(L)
            R_list.append(R)

            transcript.append(L)
            transcript.append(R)

            u = transcript.get_challenge_scalar()
            u_inv = pow(u, -1, self.E.order)
            u_list.append(u)

            for i in range(n):
                c_low[i] = (c_low[i] + c_hi[i] * u_inv) % self.E.order
                b_low[i] = (b_low[i] + b_hi[i] * u) % self.E.order

                G_low[i] = G_low[i] + u * G_hi[i]

            c = c_low
            b = b_low

            G = G_low

        c = c[0]

        return [L_list, R_list, commitment_bar, c, t_prime], evaluation

    def verify(self, commitment, proof, point, evaluation, transcript=None):

        assert self.is_setup, "Trusted setup has not been run"
        if len(proof) != 5:
            return False

        b = [pow(point, i, self.order) for i in range(self.n)]
        L_list = proof[0]
        R_list = proof[1]
        commitment_bar = proof[2]
        c = proof[3]
        t_prime = proof[4]

        if (
            commitment.is_zero()
            or commitment_bar.is_zero()
            or t_prime % self.order == 0
            or c % self.order == 0
        ):
            return False

        transcript = transcript or FiatShamirTranscript(self.name.encode(), self.order)
        transcript.append(self.G)
        transcript.append(self.H)
        transcript.append(point)
        transcript.append(evaluation)
        transcript.append(commitment)
        transcript.append(commitment_bar)

        alpha = transcript.get_challenge_scalar()

        commitment_prime = commitment + alpha * commitment_bar - t_prime * self.H
        transcript.append(commitment_prime)

        h_prime = hash_to_curve(transcript.get_challenge(), b"U", self.E.name, 1)
        C = commitment_prime + evaluation * h_prime
        transcript.append(C)

        u_list = []
        m = int(math.log2(self.n))
        for i in range(m):

            if L_list[i].is_zero() or R_list[i].is_zero():
                return False

            transcript.append(L_list[i])
            transcript.append(R_list[i])

            u = transcript.get_challenge_scalar()
            u_inv = pow(u, -1, self.E.order)
            u_list.append(u)

            C = u_inv * L_list[i] + C + u * R_list[i]

        # TODO: this can be optimized by avoiding poly multiplication
        g = Polynomial([1], self.order)
        for i in range(m):
            coeff = [1] + [0] * 2**i
            coeff[-1] = u_list[m - i - 1]
            g *= Polynomial(coeff, self.order)

        G = self.E.multiexp(self.G, g.coeffs())
        b = inner_product(b, g.coeffs(), self.order)

        return C == self.E.multiexp([G, h_prime], [c, c * b % self.order])

    def _group_evaluation(
        self,
        points_query: MultiOpeningQuery,
        x: int,
        is_verifier=False,
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
                group_map[commitment].add(point)

        result_map = defaultdict(set)
        for value, keys in group_map.items():
            result_map[frozenset(keys)].add(value)

        q_polys = []
        q_blindings = []
        r_polys = []
        points_list = []
        for points, commitments in result_map.items():
            if not is_verifier:
                polys = [
                    points_query.to_polynomial(commitment) for commitment in commitments
                ]
                q = Polynomial([0], self.order)
                for i, poly in enumerate(polys):
                    q += pow(x, i, self.order) * poly

                blindings = [
                    points_query.get_blinding(commitment) for commitment in commitments
                ]
                blind = 0
                for i, blinding in enumerate(blindings):
                    blind += pow(x, i, self.order) * blinding
                blind %= self.order
            else:
                q = self.zero_commitment()
                for i, comm in enumerate(commitments):
                    q += pow(x, i, self.order) * comm

            xs = []
            ys = []
            for i, point in enumerate(points):
                if not is_verifier:
                    evaluation = q(point)
                else:
                    evaluation = (
                        sum(
                            [
                                pow(x, j, self.order)
                                * points_query.get_evaluation(comm, point)
                                % self.order
                                for j, comm in enumerate(commitments)
                            ]
                        )
                        % self.order
                    )

                xs.append(point)
                ys.append(evaluation)

            r = lagrange_interpolation(xs, ys, self.order)

            q_polys.append(q)
            r_polys.append(r)
            points_list.append(list(points))
            if not is_verifier:
                q_blindings.append(blind)

        return q_polys, q_blindings, r_polys, points_list

    def multi_open(self, points_query: MultiOpeningQuery, transcript=None):
        """
        Implementation based on Multipoint opening argument
        (https://zcash.github.io/halo2/design/proving-system/multipoint-opening.html)
        """

        assert self.is_setup, "Trusted setup has not been run"

        transcript = transcript or FiatShamirTranscript(self.name.encode(), self.order)
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
        q_polys, q_blindings, r_polys, points_list = self._group_evaluation(
            points_query, x1
        )

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

        f_blind = get_random_int(self.order)
        f_commitment = self.commit(f_poly, f_blind)

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

        final_blinding = f_blind
        for i, blind in enumerate(q_blindings):
            final_blinding += pow(x4, i + 1, self.order) * blind
        final_blinding %= self.order

        final_commitment = self.commit(final_poly, final_blinding)
        opening_proof, _ = self.open(
            final_poly, x3, final_commitment, final_blinding, transcript
        )
        proof.append(opening_proof)

        return proof, verifier_query

    def multi_verify(
        self,
        points_query: MultiOpeningQuery,
        proof: list,
        transcript: FiatShamirTranscript = None,
    ):

        assert self.is_setup, "Trusted setup has not been run"
        assert len(proof) > 2, "Invalid proof"

        transcript = transcript or FiatShamirTranscript(self.name.encode(), self.order)
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

        q_commitments, _, r_polys, points_list = self._group_evaluation(
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

        return self.verify(
            final_commitment, opening_proof, x3, final_poly_x3, transcript
        )
