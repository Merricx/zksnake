from typing import Sequence
from joblib import Parallel, delayed

from .utils import get_n_jobs


def _insert_triplet(i, rows, triplets):
    for j, col in enumerate(rows):
        if col != 0:
            triplets.append((i, j, col))


class SparseArray:
    """
    Sparse Array object (matrix dominated by zero elements)
    structured by triplets of (row, col, value) of non-zero elements in the matrix
    first index of triplets is the length of row, col, and value 0 respectively
    """

    def __init__(self, matrix: Sequence[Sequence[int]], n_row: int, n_col: int, p: int):
        self.p = p
        self.n_row = n_row
        self.n_col = n_col
        triplets = []

        if n_row >= 8192:
            Parallel(n_jobs=get_n_jobs())(
                delayed(_insert_triplet)(i, row, triplets)
                for i, row in enumerate(matrix)
            )
        else:
            for i, row in enumerate(matrix):
                _insert_triplet(i, row, triplets)

        self.triplets = triplets

    def dot(self, vector):
        """dot product with vector"""
        result = [0] * self.n_row
        for triplet in self.triplets:
            row, col, value = triplet

            result[row] += vector[col] * value

        return [x % self.p for x in result]
