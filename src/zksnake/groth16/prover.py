from joblib import Parallel, delayed

from ..ecc import EllipticCurve, CurvePointSize
from ..qap import QAP
from ..utils import get_random_int, get_n_jobs


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
    def from_hex(cls, s: str, crv="BN128"):
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
        B = E((bx1, bx2), (by1, by2), (1, 0))
        C = E(cx, cy)

        return Proof(A, B, C)

    def to_hex(self) -> str:
        """Return hex representation of the Proof"""
        return self.A.hex() + self.B.hex() + self.C.hex()


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
        pass

    def to_hex(self) -> str:
        pass


class Prover:
    """
    Prover object

    Args:
        qap: QAP to be proved from
        key: `ProvingKey` from trusted setup
        curve: `BN128` or `BLS12_381`
    """

    def __init__(self, qap: QAP, key: ProvingKey, curve: str = "BN128"):

        self.qap = qap
        self.key = key
        self.E = EllipticCurve(curve)
        self.order = self.E.curve.curve_order

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

        A = U(self.key.tau_1) + self.key.alpha_1 + (self.key.delta_1 * r)
        B1 = V(self.key.tau_1) + self.key.beta_1 + (self.key.delta_1 * s)
        B2 = V(self.key.tau_2) + self.key.beta_2 + (self.key.delta_2 * s)
        HT = H(self.key.target_1)

        delta_witness = Parallel(n_jobs=get_n_jobs())(
            delayed(lambda point,scalar: point*scalar)(point, scalar)
            for point, scalar in zip(self.key.kdelta_1, private_witness)
        )
        sum_delta_witness = delta_witness[0]
        for k in delta_witness[1:]:
            sum_delta_witness += k

        C = (
            HT
            + sum_delta_witness
            + (A * s)
            + (B1 * r)
            + (-self.key.delta_1 * (r * s % self.order))
        )

        return Proof(A, B2, C)
