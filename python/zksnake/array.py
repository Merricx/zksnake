from typing import Sequence


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
        self.triplets_map = {}
        triplets = []

        for i, row in enumerate(matrix):
            for j, col in enumerate(row):
                if col != 0:
                    triplets.append((i, j, col))

        self.triplets = triplets

    def append(self, triplets: Sequence[tuple[int, int, int]]):
        """Add new triplet to the array"""
        for triplet in triplets:
            row, col, value = triplet
            if row not in self.triplets_map:
                self.triplets_map[row] = [(col, value)]
            else:
                self.triplets_map[row] += [(col, value)]

            self.triplets.append(tuple(triplet))

    def dot(self, vector):
        """dot product with vector"""
        result = [0] * self.n_row
        for triplet in self.triplets:
            row, col, value = triplet

            result[row] += vector[col] * value

        return [x % self.p for x in result]
