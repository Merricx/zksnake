"""Verification module of Groth16 protocol"""

from ..ecc import EllipticCurve, CurvePointSize
from .prover import Proof
from ..utils import split_list


class VerifyingKey:
    def __init__(
        self,
        alpha_G1,  # vk_alpha_1
        beta_G2,  # vk_beta_2
        gamma_G2,  # vk_gamma_2
        delta_G2,  # vk_delta_2
        IC,  # ic
    ):
        self.alpha_1 = alpha_G1
        self.beta_2 = beta_G2
        self.gamma_2 = gamma_G2
        self.delta_2 = delta_G2
        self.ic = IC

    @classmethod
    def from_hex(cls, s: str, crv="BN254"):
        """Construct VerifyingKey from hexstring"""
        E = EllipticCurve(crv)

        n = CurvePointSize[crv].value

        assert len(s) >= n * 7, "Invalid verifying key length"

        fixed_blocks = split_list(s[: n * 7], n)
        dynamic_blocks = s[n * 7 :]

        alpha_x = fixed_blocks[0]
        beta_x = fixed_blocks[1] + fixed_blocks[2]
        gamma_x = fixed_blocks[3] + fixed_blocks[4]
        delta_x = fixed_blocks[5] + fixed_blocks[6]

        ic = []
        dynamic_blocks = dynamic_blocks[16:]  # skip length header
        dynamic_blocks = split_list(dynamic_blocks, n)
        for block in dynamic_blocks:
            ic.append(E.from_hex(block))

        alpha_1 = E.from_hex(alpha_x)
        beta_2 = E.from_hex(beta_x)
        gamma_2 = E.from_hex(gamma_x)
        delta_2 = E.from_hex(delta_x)

        return VerifyingKey(alpha_1, beta_2, gamma_2, delta_2, ic)

    def to_hex(self) -> str:
        """Return hex representation of the VerifyingKey"""
        s = (
            self.alpha_1.to_hex()
            + self.beta_2.to_hex()
            + self.gamma_2.to_hex()
            + self.delta_2.to_hex()
        )

        s += int.to_bytes(len(self.ic), 8, "little").hex()
        for ic in self.ic:
            s += ic.to_hex()

        return s


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
