"""Proving module of Groth16 protocol"""

from ..ecc import EllipticCurve, CurvePointSize
from ..qap import QAP
from ..utils import get_random_int


class Proof:

    def __init__(self, A=None, B=None, C=None):
        self.A = A
        self.B = B
        self.C = C

    def __str__(self):
        return f"A = {self.A}\nB = {self.B}\nC = {self.C}"

    def __repr__(self):
        return self.__str__()

    @classmethod
    def from_hex(cls, s: str, crv="BN254"):
        """Parse Proof from hexstring"""

        E = EllipticCurve(crv)

        n = CurvePointSize[crv].value
        total_points = n * 8
        assert (
            len(s) == total_points
        ), f"Length of the Proof must equal {total_points} hex bytes"

        ax, ay = int(s[:n], 16), int(s[n : n * 2], 16)
        bx1, bx2, by1, by2 = (
            int(s[n * 2 : n * 3], 16),
            int(s[n * 3 : n * 4], 16),
            int(s[n * 4 : n * 5], 16),
            int(s[n * 5 : n * 6], 16),
        )
        cx, cy = int(s[n * 6 : n * 7], 16), int(s[n * 7 :], 16)

        A = E(ax, ay)
        B = E((bx1, bx2), (by1, by2))
        C = E(cx, cy)

        return Proof(A, B, C)

    def to_hex(self) -> str:
        """Return hex representation of the Proof"""
        if self.A.x.bit_length() <= 256:
            n = 64
        else:
            n = 96

        Ax, Ay = hex(self.A.x)[2:].zfill(n), hex(self.A.y)[2:].zfill(n)
        Cx, Cy = hex(self.C.x)[2:].zfill(n), hex(self.C.y)[2:].zfill(n)

        Bx, By = self.B.x, self.B.y
        Bx1, Bx2 = hex(Bx[0])[2:].zfill(n), hex(Bx[1])[2:].zfill(n)
        By1, By2 = hex(By[0])[2:].zfill(n), hex(By[1])[2:].zfill(n)

        return Ax + Ay + Bx1 + Bx2 + By1 + By2 + Cx + Cy


class ProvingKey:
    def __init__(
        self,
        alpha_G1,
        beta_G1,
        beta_G2,
        delta_G1,
        delta_G2,
        tau_G1,
        tau_G2,
        target_G1,
        k_delta_G1,
    ):
        self.alpha_1 = alpha_G1
        self.beta_1 = beta_G1
        self.beta_2 = beta_G2
        self.delta_1 = delta_G1
        self.delta_2 = delta_G2
        self.tau_1 = tau_G1
        self.tau_2 = tau_G2
        self.target_1 = target_G1
        self.kdelta_1 = k_delta_G1

    def from_hex(self, s: str):
        raise NotImplementedError()

    def to_hex(self) -> str:
        raise NotImplementedError()


class Prover:
    """
    Prover object

    Args:
        qap: QAP to be proved from
        key: `ProvingKey` from trusted setup
        curve: `BN254` or `BLS12_381`
    """

    def __init__(self, qap: QAP, key: ProvingKey, curve: str = "BN254"):

        self.qap = qap
        self.key = key
        self.E = EllipticCurve(curve)
        self.order = self.E.order

        if key.delta_1.is_zero() or key.delta_2.is_zero():
            raise ValueError("Key delta_1 or delta_2 is zero element!")

    def prove(self, public_witness: list, private_witness: list) -> Proof:
        """
        Prove statement from QAP by providing public and private witness
        """
        assert len(self.key.kdelta_1) == len(
            private_witness
        ), "Length of kdelta_1 and private_witness must be equal"

        r = get_random_int(self.order - 1)
        s = get_random_int(self.order - 1)

        try:
            U, V, _, H = self.qap.evaluate_witness(public_witness + private_witness)
        except ValueError as exc:
            raise ValueError("Failed to evaluate with the given witness") from exc

        A = (
            self.E.multiexp(self.key.tau_1, U.coeffs())
            + self.key.alpha_1
            + (self.key.delta_1 * r)
        )
        B1 = (
            self.E.multiexp(self.key.tau_1, V.coeffs())
            + self.key.beta_1
            + (self.key.delta_1 * s)
        )
        B2 = (
            self.E.multiexp(self.key.tau_2, V.coeffs())
            + self.key.beta_2
            + (self.key.delta_2 * s)
        )
        HZ = self.E.multiexp(self.key.target_1, H.coeffs())

        if len(private_witness) > 0:
            sum_delta_witness = self.E.multiexp(self.key.kdelta_1, private_witness)
        else:  # all inputs are public
            sum_delta_witness = self.E.G1() * 0

        C = (
            HZ
            + sum_delta_witness
            + (A * s)
            + (B1 * r)
            + (-self.key.delta_1 * (r * s % self.order))
        )

        return Proof(A, B2, C)
