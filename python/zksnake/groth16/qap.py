from zksnake.utils import next_power_of_two
from ..constant import BN254_SCALAR_FIELD
from ..arithmetization.r1cs import R1CS
from ..polynomial import (
    PolynomialRing,
    ifft,
    fft,
    mul_over_evaluation_domain,
    mul_over_fft,
)


class QAP:

    def __init__(self, p=None):
        self.a = []
        self.b = []
        self.c = []
        self.n_public = 0

        self.p = p or BN254_SCALAR_FIELD

    def from_r1cs(self, r1cs: R1CS):
        """
        Parse QAP from R1CS matrices

        Args:
            r1cs: R1CS object
        """
        self.n_public = r1cs.n_public

        next_power_2 = next_power_of_two(r1cs.A.n_row)

        self.a = r1cs.A
        self.b = r1cs.B
        self.c = r1cs.C

        self.a.n_row = next_power_2
        self.b.n_row = next_power_2
        self.c.n_row = next_power_2

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

        # polynomial interpolation via IFFT
        u = PolynomialRing(ifft(a, self.p), self.p)
        v = PolynomialRing(ifft(b, self.p), self.p)
        w = PolynomialRing(ifft(c, self.p), self.p)

        # UV = IFFT( FFT(U) * FFT(V) )
        uv = mul_over_fft(self.a.n_row, u, v, self.p)

        # H = (U * V - W) / Z
        # subtraction swap is needed to keep the evaluation domain of the polynomial intact
        hz = -(w - uv)
        h, remainder = hz.divide_by_vanishing_poly()
        if not remainder.is_zero():
            raise ValueError("(U * V - W) did not divided by Z to zero")

        return u, v, w, h
