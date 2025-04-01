from ...utils import get_random_int, inner_product, split_list
from ...polynomial import Polynomial
from ...ecc import CurvePointSize, EllipticCurve
from ...transcript import FiatShamirTranscript, hash_to_curve
from . import ipa


class RangeProofObject:

    def __init__(
        self,
        V,
        A,
        S,
        T1,
        T2,
        t,
        t_blinding,
        e_blinding,
        ipa_proof: ipa.InnerProductProof,
    ):
        self.V = V
        self.A = A
        self.S = S
        self.T1 = T1
        self.T2 = T2
        self.t = t
        self.t_blinding = t_blinding
        self.e_blinding = e_blinding
        self.ipa_proof = ipa_proof

    def to_bytes(self) -> bytes:
        s = b""
        s += bytes(self.V.to_bytes())
        s += bytes(self.A.to_bytes())
        s += bytes(self.S.to_bytes())
        s += bytes(self.T1.to_bytes())
        s += bytes(self.T2.to_bytes())
        s += bytes(self.t.to_bytes(32, "little"))
        s += bytes(self.t_blinding.to_bytes(32, "little"))
        s += bytes(self.e_blinding.to_bytes(32, "little"))
        s += self.ipa_proof.to_bytes()

        return s

    @classmethod
    def from_bytes(cls, s: bytes, crv="BN254"):

        E = EllipticCurve(crv)
        n = CurvePointSize[crv].value

        assert (len(s) - 160) % n == 0, "Invalid proof length"

        point_s = split_list(s[: 5 * n], n)
        field_s = split_list(s[5 * n : 5 * n + 32 * 3], 32)
        ipa_s = s[5 * n + 32 * 3 :]

        assert len(point_s) == 5 and len(field_s) == 3, "Malformed proof structure"

        V = E.from_hex(point_s[0].hex())
        A = E.from_hex(point_s[1].hex())
        S = E.from_hex(point_s[2].hex())
        T1 = E.from_hex(point_s[3].hex())
        T2 = E.from_hex(point_s[4].hex())
        t = int.from_bytes(field_s[0], "little")
        t_blinding = int.from_bytes(field_s[1], "little")
        e_blinding = int.from_bytes(field_s[2], "little")
        ipa_proof = ipa.InnerProductProof.from_bytes(ipa_s, crv)

        return RangeProofObject(V, A, S, T1, T2, t, t_blinding, e_blinding, ipa_proof)


class RangeProof:

    def __init__(
        self,
        bitsize: int,
        curve,
        seed=b"RangeProof",
    ):
        assert bitsize < 2**32
        self.n = bitsize
        self.E = EllipticCurve(curve)
        self.G = hash_to_curve(seed, b"G", curve, self.n)
        self.H = hash_to_curve(seed, b"H", curve, self.n)
        self.B = hash_to_curve(seed, b"B", curve, 1)
        self.B_blinding = hash_to_curve(seed, b"Blinding", curve, 1)

    def __split_lr(self, data: list):
        l = []
        r = []
        for v in data:
            l += [v]
            r += [(v - 1) % self.E.order]

        return l, r

    def __delta(self, y, z):
        sum_pow_2_y = (
            sum([pow(y, i, self.E.order) for i in range(self.n)]) % self.E.order
        )
        z_pow_3 = pow(z, 3, self.E.order)
        sum_2 = sum([pow(2, i, self.E.order) for i in range(self.n)]) % self.E.order
        return (
            ((z - pow(z, 2, self.E.order)) * sum_pow_2_y) - (z_pow_3 * sum_2)
        ) % self.E.order

    def prove(self, v: int, transcript=None):

        transcript = transcript or FiatShamirTranscript(
            self.n.to_bytes(32, "big"), field=self.E.order
        )

        # bit vectors of v
        a = [(v >> i) & 1 for i in range(self.n)]
        a_L, a_R = self.__split_lr(a)

        s_L = [get_random_int(self.E.order) for _ in range(self.n)]
        s_R = [get_random_int(self.E.order) for _ in range(self.n)]

        a_blinding = get_random_int(self.E.order)
        v_blinding = get_random_int(self.E.order)
        s_blinding = get_random_int(self.E.order)

        V = v * self.B + v_blinding * self.B_blinding
        A = (
            self.E.multiexp(self.G, a_L)
            + self.E.multiexp(self.H, a_R)
            + a_blinding * self.B_blinding
        )
        S = (
            self.E.multiexp(self.G, s_L)
            + self.E.multiexp(self.H, s_R)
            + s_blinding * self.B_blinding
        )

        transcript.append(V)
        transcript.append(A)
        transcript.append(S)

        y = transcript.get_challenge_scalar()
        z = transcript.get_challenge_scalar()

        l_0 = []
        l_1 = []
        r_0 = []
        r_1 = []
        exp_2 = 1
        exp_y = 1
        for i in range(self.n):
            l_0.append((a_L[i] - z) % self.E.order)
            l_1.append(s_L[i])

            r_0.append((exp_y * (a_R[i] + z) + z * z * exp_2) % self.E.order)
            r_1.append(exp_y * s_R[i] % self.E.order)

            exp_y *= y
            exp_2 += exp_2

        l_vecpoly = []
        r_vecpoly = []

        p = self.E.order
        for i in range(self.n):
            l_vecpoly += [Polynomial([l_0[i], l_1[i]], p)]
            r_vecpoly += [Polynomial([r_0[i], r_1[i]], p)]

        t0 = inner_product(l_0, r_0, self.E.order)
        t2 = inner_product(l_1, r_1, self.E.order)

        l0_plus_l1 = [(a + b) % p for a, b in zip(l_0, l_1)]
        r0_plus_r1 = [(a + b) % p for a, b in zip(r_0, r_1)]

        t1 = (inner_product(l0_plus_l1, r0_plus_r1, self.E.order) - t0 - t2) % p

        t_poly = Polynomial([t0, t1, t2], p)

        t1_blinding = get_random_int(p)
        t2_blinding = get_random_int(p)
        T1 = t1 * self.B + t1_blinding * self.B_blinding
        T2 = t2 * self.B + t2_blinding * self.B_blinding

        transcript.append(T1)
        transcript.append(T2)

        x = transcript.get_challenge_scalar()

        l_list = [poly(x) for poly in l_vecpoly]
        r_list = [poly(x) for poly in r_vecpoly]
        t = t_poly(x)

        t_blinding_poly = Polynomial([z * z * v_blinding, t1_blinding, t2_blinding], p)
        t_blinding = t_blinding_poly(x)
        e_blinding = (a_blinding + x * s_blinding) % p

        transcript.append(t)
        transcript.append(t_blinding)
        transcript.append(e_blinding)

        w = transcript.get_challenge_scalar()

        Q = w * self.B

        ipa_prover = ipa.InnerProductArgument(self.n, self.E.name)

        ipa_prover.G = self.G
        ipa_prover.H = [pow(y, -i, p) * self.H[i] for i in range(self.n)]
        ipa_prover.Q = Q

        ipa_proof, _, _ = ipa_prover.prove(l_list, r_list, transcript)

        return RangeProofObject(V, A, S, T1, T2, t, t_blinding, e_blinding, ipa_proof)

    def verify(self, proof: RangeProofObject, transcript=None):

        transcript = transcript or FiatShamirTranscript(
            self.n.to_bytes(32, "big"), field=self.E.order
        )

        transcript.reset()
        transcript.append(proof.V)
        transcript.append(proof.A)
        transcript.append(proof.S)

        y = transcript.get_challenge_scalar()
        z = transcript.get_challenge_scalar()

        transcript.append(proof.T1)
        transcript.append(proof.T2)

        x = transcript.get_challenge_scalar()

        transcript.append(proof.t)
        transcript.append(proof.t_blinding)
        transcript.append(proof.e_blinding)

        w = transcript.get_challenge_scalar()

        for g in self.G:
            transcript.append(g)
        for i, h in enumerate(self.H):
            hprime = pow(y, -i, self.E.order) * h
            transcript.append(hprime)

        c = get_random_int(self.E.order)

        k = len(proof.ipa_proof.L)
        challenges = []
        challenges_inv = []

        all_inv = 1
        for i in range(k):
            transcript.append(proof.ipa_proof.L[i])
            transcript.append(proof.ipa_proof.R[i])

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

        a = proof.ipa_proof.a
        b = proof.ipa_proof.b

        scalar_mul_g = [(-z - a * s[i]) % self.E.order for i in range(self.n)]
        scalar_mul_h = []

        for i in range(self.n):
            s_inv = pow(s[i], -1, self.E.order)
            rhs = z * z * pow(2, i, self.E.order) - b * s_inv

            scalar_mul_h += [(z + pow(y, -i, self.E.order) * rhs) % self.E.order]

        points = (
            [
                proof.A,
                proof.S,
                proof.V,
                proof.T1,
                proof.T2,
                self.B,
                self.B_blinding,
            ]
            + self.G
            + self.H
            + proof.ipa_proof.L
            + proof.ipa_proof.R
        )

        scalars = (
            [
                1,
                x,
                c * z * z % self.E.order,
                c * x % self.E.order,
                c * x * x % self.E.order,
                (w * (proof.t - a * b) + c * (self.__delta(y, z) - proof.t))
                % self.E.order,
                (-proof.e_blinding - c * proof.t_blinding) % self.E.order,
            ]
            + scalar_mul_g
            + scalar_mul_h
            + challenges
            + challenges_inv
        )

        final_check = self.E.multiexp(points, scalars)

        return final_check.is_zero()
