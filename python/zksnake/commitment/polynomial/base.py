from zksnake.polynomial import lagrange_interpolation


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
    
    def multi_open(self, points_query: dict, commitments: list, transcript=None):
        raise NotImplementedError()

    def verify(self, commitment, proof, opening, point, transcript=None):
        raise NotImplementedError()