from zksnake.ecc import Q_BN254
from zksnake.r1cs import R1CS
from ..polynomial import (
    PolynomialRing,
    ifft,
    fft,
    mul_over_evaluation_domain,
)


class QAP:

    def __init__(self, p=None):
        self.a = []
        self.b = []
        self.c = []
        self.n_public = 0

        self.p = p or Q_BN254

    def from_r1cs(self, r1cs: R1CS):
        """
        Parse QAP from R1CS matrices

        Args:
            r1cs: R1CS object
        """
        self.n_public = r1cs.n_public

        next_power_2 = 1 << (r1cs.A.n_row - 1).bit_length()

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

        u = PolynomialRing(ifft(a, self.p), self.p)
        v = PolynomialRing(ifft(b, self.p), self.p)
        w = PolynomialRing(ifft(c, self.p), self.p)

        u_over_fft = fft(u.coeffs() + [0] * len(u.coeffs()), self.p)
        v_over_fft = fft(v.coeffs() + [0] * len(u.coeffs()), self.p)

        # UV = IFFT( FFT(U) * FFT(V) )
        uv = mul_over_evaluation_domain(u_over_fft, v_over_fft, self.p)
        uv = PolynomialRing(ifft(uv, self.p), self.p)

        # H = (U * V - W) / Z
        # subtraction swap is needed to keep the domain of the polynomial intact
        hz = -(w - uv)
        h, remainder = hz.divide_by_vanishing_poly()
        if not remainder.is_zero():
            raise ValueError("(U * V - W) did not divided by Z to zero")

        return u, v, w, h