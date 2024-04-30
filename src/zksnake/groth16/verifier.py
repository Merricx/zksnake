from joblib import Parallel, delayed

from ..ecc import EllipticCurve
from .prover import Proof
from ..utils import get_n_jobs


class VerifyingKey:
    def __init__(self, alpha_G1, beta_G2, gamma_G2, delta_G2, IC):
        self.alpha_1 = alpha_G1
        self.beta_2 = beta_G2
        self.gamma_2 = gamma_G2
        self.delta_2 = delta_G2
        self.ic = IC

    def from_hex(self, s: str):
        pass

    def to_hex(self) -> str:
        pass


class Verifier:
    """
    Verifier object

    Args:
        key: `VerifyingKey` from trusted setup
        curve: `BN128` or `BLS12_381`
    """

    def __init__(self, key: VerifyingKey, curve: str = "BN128"):
        self.key = key
        self.E = EllipticCurve(curve)

    def verify(self, proof: Proof, public_witness: list) -> bool:
        """
        Verify proof by providing public witness
        """
        assert len(self.key.ic) == len(
            public_witness
        ), "Length of IC and public_witness must be equal"

        gamma_witness = Parallel(n_jobs=get_n_jobs())(
            delayed(lambda point, scalar: point * scalar)(point, scalar)
            for point, scalar in zip(self.key.ic, public_witness)
        )
        sum_gamma_witness = gamma_witness[0]
        for k in gamma_witness[1:]:
            sum_gamma_witness += k

        pairings = [
            (proof.B, proof.A),
            (self.key.beta_2, self.key.alpha_1),
            (self.key.gamma_2, sum_gamma_witness),
            (self.key.delta_2, proof.C),
        ]

        result = Parallel(n_jobs=get_n_jobs())(
            delayed(self.E.pairing)(a, b) for a, b in pairings
        )

        # e(B, A) == e(beta, alpha) + e(gamma, sum_gamma_witness) + e(delta, C)
        return result[0] == result[1] * result[2] * result[3]
