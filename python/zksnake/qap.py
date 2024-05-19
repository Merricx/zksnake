from zksnake._algebra import array  # pylint: disable=no-name-in-module
from .array import SparseArray
from .utils import Timer
from .polynomial import PolynomialRing, ifft


class QAP:

    def __init__(self, p):
        self.a = []
        self.b = []
        self.c = []
        self.n_public = 0

        self.p = p

    def from_r1cs(self, A: list, B: list, C: list, n_public: int):
        """
        Parse QAP from R1CS matrices

        Args:
            A, B, C: matrix A,B,C from R1CS
            n_public: number of public variables in R1CS
        """
        self.n_public = n_public

        mat_len = len(A)
        next_power_2 = 1 << (mat_len - 1).bit_length()

        # TODO: bottleneck here
        self.a = SparseArray(A, next_power_2, len(A[0]), self.p)
        self.b = SparseArray(B, next_power_2, len(B[0]), self.p)
        self.c = SparseArray(C, next_power_2, len(C[0]), self.p)

    def evaluate_witness(self, witness: list):
        """
        Evaluate QAP with witness vector. Incorrect witness value will raise an error.

        Args:
            witness: witness vector (public+private) to be evaluated

        Return:
            U, V, W, H: resulting polynomials to be proved
        """

        a = self.a.dot(witness)
        b = self.b.dot(witness)
        c = self.c.dot(witness)

        U = PolynomialRing(ifft(a, self.p), self.p)
        V = PolynomialRing(ifft(b, self.p), self.p)
        W = PolynomialRing(ifft(c, self.p), self.p)

        # TODO: replace naive mul with mul over fft
        # H = (U * V - W) / Z
        HZ = U * V - W
        H, remainder = HZ.divide_by_vanishing_poly()
        if not remainder.is_zero():
            raise ValueError("(U * V - W) did not divided by Z to zero")

        return U, V, W, H
