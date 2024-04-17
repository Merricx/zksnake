from ..ecc import EllipticCurve
from .prover import Proof

class VerifyingKey:
    def __init__(
            self,
            alpha_G1,
            beta_G2,
            gamma_G2,
            delta_G2,
            k_gamma_G1
        ):
        self.alpha1 = alpha_G1
        self.beta2 = beta_G2
        self.gamma2 = gamma_G2
        self.delta2 = delta_G2
        self.kgamma1 = k_gamma_G1

    def from_hex(self, s: str):
        pass

    def to_hex(self) -> str:
        pass

class Verifier:

    def __init__(self, key: VerifyingKey, curve: str='BN128'):
        """
        Verifier object

        Args:
            key: `VerifyingKey` from trusted setup
            curve: `BN128` or `BLS12_381`
        """
        self.key = key
        self.E = EllipticCurve(curve)

    def verify(self, proof: Proof, public_witness: list) -> bool:
        """
        Verify proof by also providing public witness
        """
        gamma_witness = [point * scalar for point, scalar in zip(self.key.kgamma1, public_witness)]
        sum_gamma_witness = gamma_witness[0]
        for k in gamma_witness[1:]:
            sum_gamma_witness += k

        # e(B, A) == e(beta, alpha) + e(gamma, sum_gamma_witness) + e(delta, C)
        return self.E.pairing(proof.B, proof.A) == \
                                              self.E.pairing(self.key.beta2, self.key.alpha1) * \
                                              self.E.pairing(self.key.gamma2, sum_gamma_witness) * \
                                              self.E.pairing(self.key.delta2, proof.C)