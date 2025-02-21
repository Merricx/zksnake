from itertools import product
from typing import List

from ..transcript import FiatShamirTranscript
from ..polynomial import MultilinearPolynomial, PolynomialRing


class SumcheckPolynomial:
    def __init__(self, n, p):
        self.n = n
        self.p = p

    def to_evaluations(self) -> List[int]:
        """Get all evaluations over boolean hypercube"""
        raise NotImplementedError

    def evaluate(self, points):
        """Evaluate polynomial at given `points`"""
        raise NotImplementedError

    def first_round(self):
        """
        First round function returning univariate polynomial
        """
        raise NotImplementedError

    def round_function(self, r):
        """
        Function executed at each sumcheck round (except first round)
        with given challenge `r` by fixing one variable,
        returning univariate polynomial
        """
        raise NotImplementedError


class Sumcheck:
    """
    Sumcheck protocol to prove sum of a multilinear Polynomial
    over boolean hypercube is computed correctly
    """

    def __init__(self, n, order):
        self.n = n
        self.order = order

    def prove(self, mlpoly, transcript=None):
        """
        Prove sumcheck protocol from given simple multilinear polynomial `mlpoly`.

        If used as subprotocol, `transcript` must be supplied to ensure that the challenges are
        generated using previous protocol components.
        """

        assert mlpoly.num_vars == self.n

        sum_claim = sum(mlpoly.to_evaluations()) % self.order
        proof = []
        r_evals = []

        transcript = transcript or FiatShamirTranscript(b"sumcheck", field=self.order)
        transcript.append(sum_claim)

        for n_round in range(1, self.n + 1):

            poly = MultilinearPolynomial(0, None, self.order)
            for b in list(product([0, 1], repeat=self.n - n_round)):
                poly += mlpoly.partial_evaluate(b)

            if n_round > 1:
                r = transcript.get_challenge_scalar()
                r_evals.insert(0, r)

                # swap most left variable to the most right position
                poly = poly.permute_evaluations(list(range(1, poly.num_vars)) + [0])
                poly = poly.partial_evaluate(r_evals)

            coeffs = poly.to_coefficients()
            uni_poly = PolynomialRing(coeffs, self.order)
            transcript.append(coeffs)
            proof.append(uni_poly)

        r = transcript.get_challenge_scalar()
        r_evals.insert(0, r)

        return sum_claim, proof, r_evals[::-1]

    def prove_arbitrary(self, poly: SumcheckPolynomial, transcript=None):
        """
        Prove sumcheck protocol from given complex `poly` instantiated by `SumcheckPolynomial`.

        If used as subprotocol, `transcript` must be supplied to ensure that the challenges are
        generated using previous protocol components.
        """
        assert poly.n == self.n

        sum_claim = sum(poly.to_evaluations()) % self.order
        proof = []
        r_evals = []

        transcript = transcript or FiatShamirTranscript(b"sumcheck", field=self.order)
        transcript.append(sum_claim)

        for n_round in range(1, self.n + 1):
            if n_round == 1:
                uni_poly = poly.first_round()
            else:
                r = transcript.get_challenge_scalar()
                r_evals.insert(0, r)
                uni_poly = poly.round_function(r_evals)

                assert proof[-1](r) == (uni_poly(0) + uni_poly(1)) % self.order

            transcript.append(uni_poly.coeffs())
            proof.append(uni_poly)

        r = transcript.get_challenge_scalar()
        r_evals.insert(0, r)

        return sum_claim, proof, r_evals[::-1]

    def verify(self, sum_claim, proof, degree_bound, transcript=None, mlpoly=None):
        """
        Verify sumcheck protocol from given sum `sum_claim`, maximum `degree_bound`, and `proof`.
        Return list of challenge `r` if proof is valid, return `False` otherwise.

        If used as subprotocol, `transcript` must be supplied to ensure that the challenges are
        generated using previous protocol components.

        Optionally, if `mlpoly` is supplied, the verifier will evaluate final check
        by themselves. Otherwise, the verifier needs to perform last check manually
        outside this function.
        """

        assert len(proof) == self.n

        r_evals = []
        prev_eval = sum_claim

        transcript = transcript or FiatShamirTranscript(b"sumcheck", field=self.order)
        transcript.append(sum_claim)

        for n_round in range(1, self.n + 1):

            poly_round = proof[n_round - 1]

            if poly_round.degree() > degree_bound:
                return False

            round_eval = (poly_round(0) + poly_round(1)) % self.order

            if n_round > 1:
                r = transcript.get_challenge_scalar()
                r_evals.insert(0, r)

                prev_eval = proof[n_round - 2](r)

            # proof[i].evaluate(r) == proof[i+1].evaluate(0) + proof[i+1].evaluate(1)
            if prev_eval != round_eval:
                return False

            transcript.append(poly_round.coeffs())

        r = transcript.get_challenge_scalar()
        r_evals.insert(0, r)

        # if mlpoly is given, verifier evaluate `r_evals` by themselves
        # otherwise, verifier can query the evaluation via other way
        # (eg. Polynomial Commitment Scheme) which must be manually handled outside this function
        if mlpoly:
            if mlpoly.evaluate(r_evals) != proof[-1](r):
                return False

        return r_evals[::-1]
