from typing import Any, Dict
from ...polynomial import lagrange_interpolation
from ...transcript import FiatShamirTranscript


class MultiOpeningQuery:

    def __init__(self):
        self.polynomials = []
        self.commitments = []
        self.opening_points = {}
        self.evaluations = {}

    def prover_query(self, polynomial, point):
        if polynomial not in self.polynomials:
            self.polynomials.append(polynomial)

        evaluation = polynomial(point)
        poly_index = self.polynomials.index(polynomial)
        if point not in self.opening_points:
            self.opening_points[point] = [poly_index]
            self.evaluations[point] = {poly_index: evaluation}
        else:
            self.opening_points[point] += [poly_index]
            self.evaluations[point][poly_index] = evaluation

    def verifier_query(self, commitment, point, evaluation):
        if commitment not in self.commitments:
            self.commitments.append(commitment)

        poly_index = self.commitments.index(commitment)
        if point not in self.opening_points:
            self.opening_points[point] = [poly_index]
            self.evaluations[point] = {poly_index: evaluation}
        else:
            self.opening_points[point] += [poly_index]
            self.evaluations[point][poly_index] = evaluation

    def to_polynomial(self, commitment):
        index = self.commitments.index(commitment)
        return self.polynomials[index]

    def to_commitment(self, polynomial):
        index = self.polynomials.index(polynomial)
        return self.commitments[index]

    def get_evaluation(self, commitment, point):
        index = self.commitments.index(commitment)
        return self.evaluations[point][index]

    def commit(self, commit_func):
        for polynomial in self.polynomials:
            self.commitments += [commit_func(polynomial)]

    def get_polynomials(self):
        item = self.polynomials
        for point, idx in self.opening_points.items():
            polys = [item[i] for i in idx]
            yield point, polys

    def get_commitments(self):
        item = self.commitments
        for point, idx in self.opening_points.items():
            commitments = [item[i] for i in idx]
            yield point, commitments


class PolynomialCommitmentScheme:

    def __init__(self, max_degree, group):
        self.degree = max_degree
        self.group = group
        self.order = None

    def list_to_poly(self, values):
        assert len(values) <= self.degree
        x_s = list(range(len(values)))

        return lagrange_interpolation(x_s, values, self.order)

    def setup(self):
        raise NotImplementedError()

    def commit(self, polynomial):
        raise NotImplementedError()

    def open(self, polynomial, point, transcript=None):
        raise NotImplementedError()

    def multi_open(
        self,
        points_query: MultiOpeningQuery,
        transcript: FiatShamirTranscript = None,
    ):
        raise NotImplementedError()

    def verify(self, commitment, proof, opening, point, transcript=None):
        raise NotImplementedError()

    def multi_verify(
        self,
        points_query: MultiOpeningQuery,
        proof,
        transcript=None,
    ):
        raise NotImplementedError()
