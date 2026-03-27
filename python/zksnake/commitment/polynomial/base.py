from abc import ABC, abstractmethod
from ...polynomial import lagrange_interpolation
from ...transcript import FiatShamirTranscript


class MultiOpeningQuery:

    def __init__(self, is_verifier=False):
        self.polynomials = []
        self.commitments = []
        self.opening_points = {}
        self.evaluations = {}
        self.blindings = []
        self.is_verifier = is_verifier

    def prover_query(self, polynomial, point):
        """Add a polynomial and its evaluation at a point to the query (prover mode)."""
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
        """Add a commitment and its evaluation at a point to the query (verifier mode)."""
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
        """Get the polynomial corresponding to a commitment."""
        index = self.commitments.index(commitment)
        return self.polynomials[index]

    def to_commitment(self, polynomial):
        """Get the commitment corresponding to a polynomial."""
        index = self.polynomials.index(polynomial)
        return self.commitments[index]

    def get_blinding(self, commitment):
        """Get the blinding factor corresponding to a commitment."""
        index = self.commitments.index(commitment)
        return self.blindings[index]

    def get_evaluation(self, commitment, point):
        """Get the evaluation corresponding to a commitment and point."""
        index = self.commitments.index(commitment)
        return self.evaluations[point][index]

    def add_polynomial(self, polynomial, commitment, blinding=None):
        """Add a polynomial, its commitment, and optional blinding factor to the query."""
        if polynomial not in self.polynomials:
            self.polynomials += [polynomial]
            self.commitments += [commitment]
            if blinding:
                self.blindings += [blinding]
            else:
                self.blindings += [1]

    def add_commitment(self, commitment):
        """Register a commitment (verifier mode, no polynomial needed)."""
        if commitment not in self.commitments:
            self.commitments.append(commitment)

    def to_verifier_query(self):
        """Convert a prover query to a verifier query, preserving commitment ordering."""
        if self.is_verifier:
            raise ValueError("Already a verifier query")

        self.is_verifier = True
        vq = MultiOpeningQuery(True)
        vq.commitments = list(self.commitments)
        vq.opening_points = {
            pt: list(indices) for pt, indices in self.opening_points.items()
        }
        vq.evaluations = {}
        for pt, poly_indices in self.opening_points.items():
            vq.evaluations[pt] = {}
            for idx in poly_indices:
                vq.evaluations[pt][idx] = self.polynomials[idx](pt)
        return vq

    def get_polynomials(self):
        """Get the polynomials corresponding to each opening point."""
        item = self.polynomials
        for point, idx in self.opening_points.items():
            polys = [item[i] for i in idx]
            yield point, polys

    def get_commitments(self):
        """Get the commitments corresponding to each opening point."""
        item = self.commitments
        for point, idx in self.opening_points.items():
            commitments = [item[i] for i in idx]
            yield point, commitments


class PolynomialCommitmentScheme(ABC):

    def __init__(self, max_degree, group):
        self.degree = max_degree
        self.group = group
        self.order = None
        self.name = ""
        self.is_setup = False

    def list_to_poly(self, values):
        assert len(values) <= self.degree
        x_s = list(range(len(values)))

        return lagrange_interpolation(x_s, values, self.order)

    @abstractmethod
    def zero_commitment(self):
        raise NotImplementedError()

    @abstractmethod
    def setup(self):
        raise NotImplementedError()

    @abstractmethod
    def commit(self, polynomial):
        raise NotImplementedError()

    @abstractmethod
    def open(self, polynomial, point):
        raise NotImplementedError()

    @abstractmethod
    def verify(self, commitment, proof, point, evaluation, transcript=None):
        raise NotImplementedError()

    @abstractmethod
    def multi_open(
        self,
        points_query: MultiOpeningQuery,
        transcript: FiatShamirTranscript = None,
    ):
        raise NotImplementedError()

    @abstractmethod
    def multi_verify(
        self,
        points_query: MultiOpeningQuery,
        proof: list,
        transcript: FiatShamirTranscript = None,
    ):

        raise NotImplementedError()
