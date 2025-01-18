from ..ecc import EllipticCurve, CurvePointSize
from ..utils import split_list

class Proof:

    def __init__(self, A, B, C):
        self.A = A
        self.B = B
        self.C = C

    def __str__(self):
        return f"A = {self.A}\nB = {self.B}\nC = {self.C}"

    def __repr__(self):
        return self.__str__()

    @classmethod
    def from_bytes(cls, s: bytes, crv="BN254"):
        """Parse Proof from serialized bytes"""

        E = EllipticCurve(crv)

        n = CurvePointSize[crv].value
        total_points = n * 4
        assert (
            len(s) == total_points
        ), f"Length of the Proof must equal {total_points} bytes"

        ax = s[:n]
        bx = s[n : n * 3]
        cx = s[n * 3 :]

        A = E.from_hex(ax.hex())
        B = E.from_hex(bx.hex())
        C = E.from_hex(cx.hex())

        return Proof(A, B, C)

    def to_bytes(self) -> bytes:
        """Return bytes representation of the Proof"""
        return bytes(self.A.to_bytes() + self.B.to_bytes() + self.C.to_bytes())


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

        n = CurvePointSize[crv].value

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
    def from_bytes(cls, s: bytes, crv="BN254"):
        """Construct VerifyingKey from bytes"""
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
        dynamic_blocks = dynamic_blocks[8:]  # skip length header
        dynamic_blocks = split_list(dynamic_blocks, n)
        for block in dynamic_blocks:
            ic.append(E.from_hex(block.hex()))

        alpha_1 = E.from_hex(alpha_x.hex())
        beta_2 = E.from_hex(beta_x.hex())
        gamma_2 = E.from_hex(gamma_x.hex())
        delta_2 = E.from_hex(delta_x.hex())

        return VerifyingKey(alpha_1, beta_2, gamma_2, delta_2, ic)

    def to_bytes(self) -> bytes:
        """Return bytes representation of the VerifyingKey"""
        s = bytes(
            self.alpha_1.to_bytes()
            + self.beta_2.to_bytes()
            + self.gamma_2.to_bytes()
            + self.delta_2.to_bytes()
        )

        s += int.to_bytes(len(self.ic), 8, "little")
        for ic in self.ic:
            s += bytes(ic.to_bytes())

        return s
