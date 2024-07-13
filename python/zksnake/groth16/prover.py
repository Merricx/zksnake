"""Proving module of Groth16 protocol"""

from ..ecc import EllipticCurve, CurvePointSize
from ..qap import QAP
from ..utils import get_random_int, split_list


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
        total_points = n * 4
        assert (
            len(s) == total_points
        ), f"Length of the Proof must equal {total_points} hex bytes"

        ax = s[:n]
        bx = s[n : n * 3]
        cx = s[n * 3 :]

        A = E.from_hex(ax)
        B = E.from_hex(bx)
        C = E.from_hex(cx)

        return Proof(A, B, C)

    def to_hex(self) -> str:
        """Return hex representation of the Proof"""
        return self.A.to_hex() + self.B.to_hex() + self.C.to_hex()


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

    @classmethod
    def from_bytes(cls, s: bytes, crv="BN254"):
        """Construct ProvingKey from bytes"""
        E = EllipticCurve(crv)

        n = CurvePointSize[crv].value // 2

        fixed_blocks = s[: n * 7]
        dynamic_blocks = s[n * 7 :]
        s = split_list(fixed_blocks, n)

        assert len(s) >= 7, "Invalid proving key length"

        alpha_x = s[0]
        beta2_x = s[1] + s[2]
        delta2_x = s[3] + s[4]
        beta1_x = s[5]
        delta1_x = s[6]

        tau_g1_length = int.from_bytes(dynamic_blocks[:8], "little")
        dynamic_blocks = dynamic_blocks[8:]
        tau_g1_blocks = split_list(dynamic_blocks[: tau_g1_length * n], n)
        dynamic_blocks = dynamic_blocks[tau_g1_length * n :]

        tau_g2_length = int.from_bytes(dynamic_blocks[:8], "little")
        dynamic_blocks = dynamic_blocks[8:]
        tau_g2_blocks = split_list(dynamic_blocks[: tau_g2_length * n * 2], n * 2)
        dynamic_blocks = dynamic_blocks[tau_g2_length * n * 2 :]

        target_g1_length = int.from_bytes(dynamic_blocks[:8], "little")
        dynamic_blocks = dynamic_blocks[8:]
        target_g1_blocks = split_list(dynamic_blocks[: target_g1_length * n], n)
        dynamic_blocks = dynamic_blocks[target_g1_length * n :]

        kdelta_g1_length = int.from_bytes(dynamic_blocks[:8], "little")
        dynamic_blocks = dynamic_blocks[8:]
        kdelta_g1_blocks = split_list(dynamic_blocks[: kdelta_g1_length * n], n)
        dynamic_blocks = dynamic_blocks[kdelta_g1_length * n :]

        alpha_1 = E.from_hex(alpha_x.hex())
        beta_2 = E.from_hex(beta2_x.hex())
        delta_2 = E.from_hex(delta2_x.hex())
        beta_1 = E.from_hex(beta1_x.hex())
        delta_1 = E.from_hex(delta1_x.hex())

        tau_1 = []
        for block in tau_g1_blocks:
            tau_1.append(E.from_hex(block.hex()))

        tau_2 = []
        for block in tau_g2_blocks:
            tau_2.append(E.from_hex(block.hex()))

        target_1 = []
        for block in target_g1_blocks:
            target_1.append(E.from_hex(block.hex()))

        kdelta_1 = []
        for block in kdelta_g1_blocks:
            kdelta_1.append(E.from_hex(block.hex()))

        return ProvingKey(
            alpha_1, beta_1, beta_2, delta_1, delta_2, tau_1, tau_2, target_1, kdelta_1
        )

    def to_bytes(self) -> bytes:
        """Return bytes representation of the ProvingKey"""
        s = (
            self.alpha_1.to_bytes()
            + self.beta_2.to_bytes()
            + self.delta_2.to_bytes()
            + self.beta_1.to_bytes()
            + self.delta_1.to_bytes()
        )

        s += int.to_bytes(len(self.tau_1), 8, "little")
        for t in self.tau_1:
            s += t.to_bytes()

        s += int.to_bytes(len(self.tau_2), 8, "little")
        for t in self.tau_2:
            s += t.to_bytes()

        s += int.to_bytes(len(self.target_1), 8, "little")
        for t in self.target_1:
            s += t.to_bytes()

        s += int.to_bytes(len(self.kdelta_1), 8, "little")
        for k in self.kdelta_1:
            s += k.to_bytes()

        return bytes(s)


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
