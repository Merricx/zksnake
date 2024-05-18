"""Verification module of Groth16 protocol"""

from ..ecc import EllipticCurve
from .prover import Proof


class VerifyingKey:
    def __init__(
        self,
        alpha_G1,
        beta_G2,
        gamma_G2,
        delta_G2,
        IC,
    ):
        self.alpha_1 = alpha_G1
        self.beta_2 = beta_G2
        self.gamma_2 = gamma_G2
        self.delta_2 = delta_G2
        self.ic = IC

    def from_hex(self, s: str):
        raise NotImplementedError()

    def to_hex(self) -> str:
        raise NotImplementedError()


class Verifier:
    """
    Verifier object

    Args:
        key: `VerifyingKey` from trusted setup
        curve: `BN254` or `BLS12_381`
    """

    def __init__(self, key: VerifyingKey, curve: str = "BN254"):
        self.key = key
        self.E = EllipticCurve(curve)

    def verify(self, proof: Proof, public_witness: list) -> bool:
        """
        Verify proof by providing public witness
        """
        assert len(self.key.ic) == len(
            public_witness
        ), "Length of IC and public_witness must be equal"

        sum_gamma_witness = self.E.multiexp(self.key.ic, public_witness)

        # e(A, B) == e(alpha, beta) + e(sum_gamma_witness, gamma) + e(C, delta)
        return self.E.pairing(proof.A, proof.B) == self.E.multi_pairing(
            [self.key.alpha_1, sum_gamma_witness, proof.C],
            [self.key.beta_2, self.key.gamma_2, self.key.delta_2],
        )
