from itertools import product
from typing import List
from ..polynomial import MultilinearPolynomial, PolynomialRing

def boolean_hypercube(num_vars):
    """
    Get list of all boolean hypercube
    """
    return list(product([0, 1], repeat=num_vars))

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

    def prove(self, mlpoly, r_challenges):
        """
        Prove sumcheck protocol from given multilinear polynomial `mlpoly`
        with provided random challenges `r_challenges` from verifier (Fiat-Shamir transcript).
        """

        assert mlpoly.num_vars == self.n
        assert len(r_challenges) == self.n

        sum_claim = sum(mlpoly.to_evaluations()) % self.order
        proof = []
        r_evals = []

        for n_round in range(1, self.n+1):

            poly = MultilinearPolynomial(0,None,self.order)
            for b in list(product([0, 1], repeat=self.n - n_round)):
                poly += mlpoly.partial_evaluate(b)

            if n_round > 1:
                r = r_challenges[n_round-2]
                r_evals.insert(0, r)

                # swap most left variable to the most right position
                poly = poly.permute_evaluations(list(range(1, poly.num_vars)) + [0])
                poly = poly.partial_evaluate(r_evals)

            uni_poly = PolynomialRing(poly.to_coefficients(), self.order)
            proof.append(uni_poly)

        return sum_claim, proof

    def prove_arbitrary(self, poly: SumcheckPolynomial, r_challenges: List[int]):
        """
        Prove sumcheck protocol from given arbitrary `poly` instantiated by `SumcheckPolynomial`
        with provided random challenges `r_challenges` from verifier (Fiat-Shamir transcript).
        """
        assert poly.n == self.n
        assert len(r_challenges) == self.n

        sum_claim = sum(poly.to_evaluations()) % self.order
        proof = []
        r_evals = []

        for n_round in range(1, self.n+1):
            if n_round == 1:
                uni_poly = poly.first_round()
            else:
                r = r_challenges[n_round-2]
                r_evals += [r]
                uni_poly = poly.round_function(r_evals)

                assert proof[-1](r) == (uni_poly(0) + uni_poly(1)) % self.order

            proof.append(uni_poly)

        return sum_claim, proof

    def verify(self, sum_claim, proof, r_challenges: List[int], mlpoly=None):
        """
        Verify sumcheck protocol from given sum `sum_claim` and `proof`
        with provided random challenges `r_challenges` (generated via Fiat-Shamir transcript).
        
        Optionally, if `mlpoly` supplied, the verifier will evaluate final check
        by themselves. Otherwise, the verifier needs to evaluate via
        Polynomial Commitment Scheme which handled manually outside this function
        """

        assert len(proof) == self.n
        assert len(r_challenges) == self.n

        r_evals = []
        prev_eval = sum_claim

        for n_round in range(1, self.n+1):

            poly_round = proof[n_round-1]
            round_eval = (
                poly_round(0) +
                poly_round(1)
            ) % self.order

            if n_round > 1:
                r = r_challenges[n_round-2]
                r_evals.insert(0, r)

                prev_eval = proof[n_round-2](r)

            # proof[i].evaluate(r) == proof[i+1].evaluate(0) + proof[i+1].evaluate(1)
            if prev_eval != round_eval:
                return False

        # if mlpoly is given, verifier evaluate `r_evals` by themselves
        # otherwise, verifier can query the evaluation via Polynomial Commitment Scheme
        # which must be manually handled outside this function
        if mlpoly:
            if mlpoly.evaluate(r_challenges[::-1]) != proof[-1](r_challenges[-1]):
                return False

        return True
