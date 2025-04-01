from ...utils import inner_product, next_power_of_two, split_list
from ...transcript import FiatShamirTranscript, hash_to_curve
from ...ecc import CurvePointSize, EllipticCurve


class InnerProductProof:

    def __init__(self, a: int, b: int, L: list, R: list):
        self.a = a
        self.b = b
        self.L = L
        self.R = R

    def to_bytes(self) -> bytes:
        s = b""
        for _, (L, R) in enumerate(zip(self.L, self.R)):
            s += bytes(L.to_bytes())
            s += bytes(R.to_bytes())

        s += self.a.to_bytes(32, "little")
        s += self.b.to_bytes(32, "little")

        return bytes(s)

    @classmethod
    def from_bytes(cls, s: bytes, crv="BN254"):

        E = EllipticCurve(crv)
        n = CurvePointSize[crv].value

        assert (len(s) - 64) % n == 0, "Invalid proof length"

        Ls = []
        Rs = []

        field_s = split_list(s[-64:], 32)
        s = split_list(s[:-64], n)

        for i in range(0, len(s), 2):
            Ls.append(E.from_hex(s[i].hex()))
            Rs.append(E.from_hex(s[i + 1].hex()))

        a = int.from_bytes(field_s[0], "little")
        b = int.from_bytes(field_s[1], "little")

        return InnerProductProof(a, b, Ls, Rs)


class InnerProductArgument:

    def __init__(
        self,
        size,
        curve,
        seed=b"InnerProductProof",
        Q=None,
    ):
        self.n = next_power_of_two(size)
        self.E = EllipticCurve(curve)
        self.G = hash_to_curve(seed, b"G", curve, self.n)
        self.H = hash_to_curve(seed, b"H", curve, self.n)
        self.Q = Q

    def __split_half(self, data: list):
        if len(data) > 2:
            mid_index = len(data) // 2
            return data[:mid_index], data[mid_index:]
        elif len(data) == 2:
            return [data[0]], [data[1]]
        else:
            return [data[0]], []

    def prove(self, a: list, b: list, transcript=None):

        transcript = transcript or FiatShamirTranscript(
            self.n.to_bytes(32, "big"), field=self.E.order
        )

        # pad a and b to the size
        a = a + [0 for _ in range(self.n - len(a))]
        b = b + [0 for _ in range(self.n - len(b))]

        for g in self.G:
            transcript.append(g)
        for h in self.H:
            transcript.append(h)

        ab = inner_product(a, b, self.E.order)

        commitment = self.E.multiexp(self.G + self.H, a + b)
        if self.Q:
            Q = self.Q
        else:
            transcript.append(commitment)
            Q = hash_to_curve(transcript.get_challenge(), b"Q", self.E.name)

        L_list = []
        R_list = []
        u_list = []

        n = self.n
        G = self.G
        H = self.H

        while n != 1:
            n //= 2

            a_low, a_hi = self.__split_half(a)
            b_low, b_hi = self.__split_half(b)
            G_low, G_hi = self.__split_half(G)
            H_low, H_hi = self.__split_half(H)

            L = (
                self.E.multiexp(G_hi, a_low)
                + self.E.multiexp(H_low, b_hi)
                + inner_product(a_low, b_hi, self.E.order) * Q
            )
            R = (
                self.E.multiexp(G_low, a_hi)
                + self.E.multiexp(H_hi, b_low)
                + inner_product(a_hi, b_low, self.E.order) * Q
            )

            L_list.append(L)
            R_list.append(R)

            transcript.append(L)
            transcript.append(R)

            u = transcript.get_challenge_scalar()
            u_inv = pow(u, -1, self.E.order)
            u_list.append(u)

            for i in range(n):
                a_low[i] = (a_low[i] * u + a_hi[i] * u_inv) % self.E.order
                b_low[i] = (b_low[i] * u_inv + b_hi[i] * u) % self.E.order

                G_low[i] = self.E.multiexp([G_low[i], G_hi[i]], [u_inv, u])
                H_low[i] = self.E.multiexp([H_low[i], H_hi[i]], [u, u_inv])

            a = a_low
            b = b_low

            G = G_low
            H = H_low

        a = a[0]
        b = b[0]

        return InnerProductProof(a, b, L_list, R_list), commitment, ab

    def verify(
        self,
        proof: InnerProductProof,
        commitment,
        inner_product_result,
        transcript=None,
    ):

        assert len(proof.L) < 32, "Argument size is too big"

        transcript = transcript or FiatShamirTranscript(
            self.n.to_bytes(32, "big"), field=self.E.order
        )

        for g in self.G:
            transcript.append(g)
        for h in self.H:
            transcript.append(h)

        transcript.append(commitment)
        Q = hash_to_curve(transcript.get_challenge(), b"Q", self.E.name)

        k = len(proof.L)
        challenges = []
        challenges_inv = []

        all_inv = 1
        for i in range(k):
            transcript.append(proof.L[i])
            transcript.append(proof.R[i])

            u = transcript.get_challenge_scalar()

            challenges.append(pow(u, 2, self.E.order))
            challenges_inv.append(pow(u, -2, self.E.order))
            all_inv *= pow(u, -1, self.E.order)

        s = [all_inv]
        for i in range(1, self.n):
            lg_i = 32 - 1 - (32 - i.bit_length())
            l = 1 << lg_i

            u_lg_i_sq = challenges[(k - 1) - lg_i]
            s.append(s[i - l] * u_lg_i_sq)

        a_s = [proof.a * x % self.E.order for x in s]
        b_s_inv = [proof.b * pow(x, -1, self.E.order) % self.E.order for x in s]

        sum_LR = self.E.curve.PointG1.identity()
        for j in range(k):
            sum_LR += proof.L[j] * challenges[j] + proof.R[j] * challenges_inv[j]

        lhs = commitment + inner_product_result * Q

        rhs = (
            self.E.multiexp(self.G, a_s)
            + self.E.multiexp(self.H, b_s_inv)
            + proof.a * proof.b * Q
            - sum_LR
        )

        return lhs == rhs
