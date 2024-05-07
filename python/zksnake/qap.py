from zksnake._algebra import array  # pylint: disable=no-name-in-module

from .polynomial import PolynomialRing, ifft

fft_cache = {}


class QAP:

    def __init__(self, p):
        self.U = []
        self.V = []
        self.W = []
        self.n_public = 0

        self.p = p

    def _r1cs_to_qap_reduction(self, m, poly_m, index):
        poly_list = []

        for i in range(len(m[0])):
            y = [0] * len(m)
            for j in range(len(m)):
                y[j] = m[j][i]

            if tuple(y) not in fft_cache:
                poly = ifft(y, self.p)
                fft_cache[tuple(y)] = poly
            else:
                poly = fft_cache[tuple(y)]

            poly_list.append(poly)

        poly_m[index] = poly_list

    def from_r1cs(self, A: list, B: list, C: list, n_public: int):
        """
        Parse QAP from R1CS matrices

        Args:
            A, B, C: matrix A,B,C from R1CS compile result
            n_public: number of public variables in R1CS
        """
        mat = (A, B, C)
        self.n_public = n_public

        poly_m = [[]] * 3

        for i, m in enumerate(mat):
            self._r1cs_to_qap_reduction(m, poly_m, i)

        self.U, self.V, self.W = poly_m[0], poly_m[1], poly_m[2]

        fft_cache.clear()

    def evaluate_witness(self, witness: list):
        """
        Evaluate QAP with witness vector. Incorrect witness value will raise an error.

        Args:
            witness: witness vector (public+private) to be evaluated

        Return:
            U, V, W, H: resulting polynomials to be proved
        """

        poly_m = []
        for m in (self.U, self.V, self.W):
            result = array.dot_product(witness, m, self.p)
            poly_m.append(PolynomialRing(result, self.p))

        U, V, W = poly_m[0], poly_m[1], poly_m[2]

        # H = (U * V - W) / Z
        UVW = U * V - W
        H, remainder = UVW.divide_by_vanishing_poly()
        if not remainder.is_zero():
            raise ValueError("(U * V - W) / T did not divide to zero")

        return U, V, W, H
