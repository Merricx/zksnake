from joblib import Parallel, delayed
from .polynomial import (
    PolynomialRing,
    vanishing_polynomial,
)
from .ntt import build_omega, CPU_INTT, clear_ntt_cache
from .utils import get_n_jobs


class QAP:

    def __init__(self, p):
        self.U = []
        self.V = []
        self.W = []
        self.T = PolynomialRing([0], p)
        self.n_public = 0

        self.p = p

    def _r1cs_to_qap_reduction(self, m, poly_m, index):
        poly_list = []

        ys = []
        next_power_2 = 1 << (len(m) - 1).bit_length()

        _, omega_inv_list = build_omega(next_power_2, self.p)
        for i in range(len(m[0])):
            y = [0] * next_power_2
            for j in range(len(m)):
                y[j] = m[j][i]

            ys.append(y)

        poly_list = Parallel(n_jobs=get_n_jobs())(
            delayed(CPU_INTT)(y, omega_inv_list, self.p) for y in ys
        )

        poly_m[index] = poly_list

    def from_r1cs(self, A: list, B: list, C: list, n_public: int):
        """
        Parse QAP from R1CS matrices

        Args:
            A, B, C: Matrix A,B,C from R1CS compile result
            n_public: Number of public variables in R1CS
        """
        mat = (A, B, C)
        self.n_public = n_public

        poly_m = [[]] * 3

        for i, m in enumerate(mat):
            self._r1cs_to_qap_reduction(m, poly_m, i)

        self.U, self.V, self.W = poly_m[0], poly_m[1], poly_m[2]
        self.T = vanishing_polynomial(len(poly_m[0][0]), self.p)

        clear_ntt_cache()

    def evaluate_witness(self, witness: list):
        """
        Evaluate QAP with witness vector. Incorrect witness value will raise an error.

        Args:
            witness: Witness vector (public+private) to be evaluated

        Return:
            U, V, W, H: Resulting polynomials to be proved
        """

        poly_m = []
        for m in (self.U, self.V, self.W):
            result = []
            # dot product of <witness> . [poly_list]
            for i in range(len(m[0])):
                result += [sum(witness[j] * m[j][i] for j in range(len(witness)))]

            poly_m.append(PolynomialRing(result, self.p))

        U, V, W = poly_m[0], poly_m[1], poly_m[2]

        H, remainder = (U * V - W) / self.T
        if not remainder.is_zero():
            raise ValueError("(U * V - W) / T did not divide to zero")

        return U, V, W, H
