from ..transcript import FiatShamirTranscript
from ..utils import Timer, batch_modinv, get_random_int, split_list
from ..ecc import CurvePointSize, EllipticCurve
from ..polynomial import PolynomialRing, fft, get_all_root_of_unity, ifft, mul_over_evaluation_domain, mul_over_fft


class ProvingKey:
    def __init__(
        self,
        n,
        tau_G1,
        tau_G2,
        selector_poly,
        permutation_poly,
        identity_poly,
        tau_selector,
        tau_permutation,
        curve: str = "BN254"
    ):
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.n = n
        self.tau_g1 = tau_G1
        self.tau_g2 = tau_G2
        self.selector_poly = selector_poly
        self.permutation_poly = permutation_poly
        self.identity_poly = identity_poly

        self.tau_selector_poly = tau_selector
        self.tau_permutation_poly = tau_permutation

class Prover:
    def __init__(self, key: ProvingKey, label: str = "PlonK"):
        self.key = key
        self.n = key.n
        self.E = key.E
        self.order = key.order
        self.label = label

    def prove(self, public_witness, private_witness):

        a = private_witness[::3] + [0]*(self.n - len(private_witness[::3]))
        b = private_witness[1::3] + [0]*(self.n - len(private_witness[1::3]))
        c = private_witness[2::3] + [0]*(self.n - len(private_witness[2::3]))
        public_witness += [0]*(self.n - len(public_witness))

        transcript = FiatShamirTranscript(self.label.encode())
        roots = get_all_root_of_unity(self.n, self.order)

        # vanishing polynomial X^n - 1
        Zh = PolynomialRing([-1 % self.order]+[0]*(self.n-1)+[1], self.order)

        QL = self.key.selector_poly['L']
        QR = self.key.selector_poly['R']
        QO = self.key.selector_poly['O']
        QM = self.key.selector_poly['M']
        QC = self.key.selector_poly['C']

        id1, id2, id3 = self.key.identity_poly
        sigma1, sigma2, sigma3 = self.key.permutation_poly

        tau_QL = self.key.tau_selector_poly['L']
        tau_QR = self.key.tau_selector_poly['R']
        tau_QO = self.key.tau_selector_poly['O']
        tau_QM = self.key.tau_selector_poly['M']
        tau_QC = self.key.tau_selector_poly['C']
        tau_sigma1 = self.key.tau_permutation_poly[0]
        tau_sigma2 = self.key.tau_permutation_poly[1]
        tau_sigma3 = self.key.tau_permutation_poly[2]

        A = PolynomialRing(ifft(a, self.order), self.order)
        B = PolynomialRing(ifft(b, self.order), self.order)
        C = PolynomialRing(ifft(c, self.order), self.order)
        PI = PolynomialRing(ifft(public_witness, self.order), self.order)

        transcript.append(self.n)
        transcript.append(self.key.tau_g1)
        transcript.append(self.key.tau_g2)
        transcript.append(tau_QL)
        transcript.append(tau_QR)
        transcript.append(tau_QO)
        transcript.append(tau_QM)
        transcript.append(tau_QC)
        transcript.append(tau_sigma1)
        transcript.append(tau_sigma2)
        transcript.append(tau_sigma3)

        #########################################################################################
        # ROUND 1
        #########################################################################################

        with Timer('round1'):

            zero_pad = [0]*(self.n-2)
            blinding_a = PolynomialRing([get_random_int(self.order-1) for _ in range(2)]+zero_pad, self.order)
            blinding_b = PolynomialRing([get_random_int(self.order-1) for _ in range(2)]+zero_pad, self.order)
            blinding_c = PolynomialRing([get_random_int(self.order-1) for _ in range(2)]+zero_pad, self.order)
            
            A = A+blinding_a.multiply_by_vanishing_poly()
            B = B+blinding_b.multiply_by_vanishing_poly()
            C = C+blinding_c.multiply_by_vanishing_poly()

            A_QL = mul_over_fft(self.n, A, QL, self.order,)
            B_QR = mul_over_fft(self.n, B, QR, self.order)
            C_QO = mul_over_fft(self.n, C, QO, self.order)
            AB = mul_over_fft(self.n, A, B, self.order, False)
            AB_QM = mul_over_fft(self.n, AB, QM, self.order)

            G = A_QL + B_QR + AB_QM + C_QO + QC + PI

            tau_a = self.E.multiexp(self.key.tau_g1, A.coeffs())
            tau_b = self.E.multiexp(self.key.tau_g1, B.coeffs())
            tau_c = self.E.multiexp(self.key.tau_g1, C.coeffs())

            transcript.append(tau_a)
            transcript.append(tau_b)
            transcript.append(tau_c)

        #########################################################################################
        # ROUND 2
        #########################################################################################

        with Timer('round2 A'):

            transcript.append(0)
            beta = transcript.get_challenge_scalar() % self.order
            transcript.append(1)
            gamma = transcript.get_challenge_scalar() % self.order

            zero_pad = [0]*(self.n-3)
            blinding_permutation = PolynomialRing([get_random_int(self.order-1) for _ in range(3)]+zero_pad, self.order)

            nom_poly = mul_over_fft(
                self.n, mul_over_fft(
                    self.n, 
                    (A + id1 * beta + gamma), 
                    (B + id2 * beta + gamma), self.order), 
                    (C + id3 * beta + gamma),
                self.order)
            
            denom_poly = mul_over_fft(
                self.n, mul_over_fft(
                    self.n, 
                    (A + sigma1 * beta + gamma), 
                    (B + sigma2 * beta + gamma), self.order), 
                    (C + sigma3 * beta + gamma),
                self.order)

        with Timer('round2 B'):

            eval_nom_poly = fft(nom_poly.coeffs(), self.order)
            eval_denom_poly = fft(denom_poly.coeffs(), self.order)
            nom_inv_denom = batch_modinv([eval_denom_poly[i] for i in range(0, len(eval_denom_poly), 4)], self.order)
            
            accumulator = [1]
            for i in range(self.n):
                accumulator += [accumulator[-1] * eval_nom_poly[i*4] * nom_inv_denom[i] % self.order]

            assert accumulator.pop() == 1, "Copy constraints are not satisfied"

        with Timer('round2 C'):

            acc_poly = PolynomialRing(ifft(accumulator, self.order), self.order)

        with Timer('round2 D'):

            Z = blinding_permutation.multiply_by_vanishing_poly() + acc_poly
            tau_z = self.E.multiexp(self.key.tau_g1, Z.coeffs())
            
            transcript.append(tau_z)

        #########################################################################################
        # ROUND 3
        #########################################################################################

        with Timer('round3 A'):

            alpha = transcript.get_challenge_scalar() % self.order
            
            Z_omega = PolynomialRing([coeff * roots[i % self.n] % self.order for i, coeff in enumerate(Z.coeffs())], self.order)
            L1 = PolynomialRing(ifft([1] + [0]*(self.n-1), self.order), self.order)

            nom_poly_Z = mul_over_fft(self.n, nom_poly, Z, self.order)
            denom_poly_Z_omega = mul_over_fft(self.n, denom_poly, Z_omega, self.order)
            Z_1_L1 = mul_over_fft(self.n, (Z - 1), L1, self.order)

            T, remainder = (
                G + (nom_poly_Z - denom_poly_Z_omega) * alpha +
                Z_1_L1 * pow(alpha, 2, self.order)
            ).divide_by_vanishing_poly()

            assert remainder.is_zero()

        with Timer('round3 B'):

            t_coeff = T.coeffs()
            T_lo  = PolynomialRing(t_coeff[:self.n], self.order)
            T_mid = PolynomialRing(t_coeff[self.n:2*self.n], self.order)
            T_hi  = PolynomialRing(t_coeff[2*self.n:], self.order)

            X_n  = PolynomialRing([0]*(self.n) + [1], self.order)


        with Timer('round3 C'):

            blindings = [get_random_int(self.order-1) for _ in range(2)]

            T_lo  = T_lo + X_n * blindings[0]
            T_mid = T_mid - blindings[0] + X_n * blindings[1]
            T_hi  = T_hi - blindings[1]


        with Timer('round3 D'):

            tau_T_lo  = self.E.multiexp(self.key.tau_g1, T_lo.coeffs())
            tau_T_mid = self.E.multiexp(self.key.tau_g1, T_mid.coeffs())
            tau_T_hi  = self.E.multiexp(self.key.tau_g1, T_hi.coeffs())

            transcript.append(tau_T_lo)
            transcript.append(tau_T_mid)
            transcript.append(tau_T_hi)

        #########################################################################################
        # ROUND 4
        #########################################################################################

        with Timer('round4'):

            zeta = transcript.get_challenge_scalar() % self.order

            zeta_A = A(zeta)
            zeta_B = B(zeta)
            zeta_C = C(zeta)
            zeta_sigma1 = sigma1(zeta)
            zeta_sigma2 = sigma2(zeta)
            zeta_Z_omega = Z_omega(zeta)

            transcript.append(zeta_A)
            transcript.append(zeta_B)
            transcript.append(zeta_C)
            transcript.append(zeta_sigma1)
            transcript.append(zeta_sigma2)
            transcript.append(zeta_Z_omega)

        #########################################################################################
        # ROUND 5
        #########################################################################################

        with Timer('round5'):

            v = transcript.get_challenge_scalar() % self.order

            k1 = 2
            k2 = 3
            R = (
                (QL * zeta_A + QR * zeta_B + QO * zeta_C + QM * zeta_A * zeta_B + QC + PI(zeta)) +
                alpha * ((zeta_A + beta * zeta + gamma) * 
                (zeta_B + beta * k1 * zeta + gamma) * 
                (zeta_C + beta * k2 * zeta + gamma) * Z -
                (zeta_A + beta * zeta_sigma1 + gamma) *
                (zeta_B + beta * zeta_sigma2 + gamma) *
                (sigma3 * beta + zeta_C + gamma) * zeta_Z_omega) +
                pow(alpha, 2, self.order) * ((Z - 1) * L1(zeta)) -
                ((T_lo + pow(zeta, self.n, self.order) * T_mid + T_hi * pow(zeta, self.n*2, self.order)) * Zh(zeta))
            )

            W_zeta = (
                R + 
                (A - zeta_A) * v +
                (B - zeta_B) * pow(v, 2, self.order) +
                (C - zeta_C) * pow(v, 3, self.order) +
                (sigma1 - zeta_sigma1) * pow(v, 4, self.order) +
                (sigma2 - zeta_sigma2) * pow(v, 5, self.order)
            )
            divisor_W_zeta = PolynomialRing([-zeta % self.order, 1], self.order)

            W_zeta, remainder = W_zeta / divisor_W_zeta

            assert remainder.is_zero()

            divisor_W_zeta_omega = PolynomialRing([-(zeta*roots[1]) % self.order, 1], self.order)
            W_zeta_omega, remainder = (Z - zeta_Z_omega) / divisor_W_zeta_omega

            assert remainder.is_zero()

            tau_W_zeta = self.E.multiexp(self.key.tau_g1, W_zeta.coeffs())
            tau_W_zeta_omega = self.E.multiexp(self.key.tau_g1, W_zeta_omega.coeffs())

        return Proof(
            tau_a, tau_b, tau_c, tau_z,
            tau_T_lo, tau_T_mid, tau_T_hi,
            tau_W_zeta, tau_W_zeta_omega,
            zeta_A, zeta_B, zeta_C, zeta_sigma1, zeta_sigma2, zeta_Z_omega
        )


class Proof:

    def __init__(
            self,
            tau_a,
            tau_b,
            tau_c,
            tau_z,
            tau_t_lo,
            tau_t_mid,
            tau_t_hi,
            tau_W_zeta,
            tau_W_zeta_omega,
            zeta_a,
            zeta_b,
            zeta_c,
            zeta_sigma1,
            zeta_sigma2,
            zeta_omega
        ):
        self.tau_a = tau_a
        self.tau_b = tau_b
        self.tau_c = tau_c
        self.tau_z = tau_z
        self.tau_t_lo = tau_t_lo
        self.tau_t_mid = tau_t_mid
        self.tau_t_hi = tau_t_hi
        self.tau_W_zeta = tau_W_zeta
        self.tau_W_zeta_omega = tau_W_zeta_omega
        self.zeta_a = zeta_a
        self.zeta_b = zeta_b
        self.zeta_c = zeta_c
        self.zeta_sigma1 = zeta_sigma1
        self.zeta_sigma2 = zeta_sigma2
        self.zeta_omega = zeta_omega

    @classmethod
    def from_hex(cls, s: str, crv="BN254"):
        """Parse Proof from hexstring"""

        E = EllipticCurve(crv)

        n = CurvePointSize[crv].value
        total_points = n * 9
        total_scalars = 32*2 * 6
        assert (
            len(s) == total_points + total_scalars
        ), f"Length of the Proof must equal {total_points + total_scalars} hex bytes"

        ax = s[:n]
        bx = s[n : n * 2]
        cx = s[n * 2 : n * 3]
        zx = s[n * 3 : n * 4]
        tlox = s[n * 4 : n * 5]
        tmix = s[n * 5 : n * 6]
        thix = s[n * 6 : n * 7]
        wzx = s[n * 7 : n * 8]
        wzox = s[n * 8 : n * 9]

        scalars = split_list(bytes.fromhex(s[n*9:]), 32)

        tau_a = E.from_hex(ax)
        tau_b = E.from_hex(bx)
        tau_c = E.from_hex(cx)
        tau_z = E.from_hex(zx)
        tau_t_lo = E.from_hex(tlox)
        tau_t_mid = E.from_hex(tmix)
        tau_t_hi = E.from_hex(thix)
        tau_w_zeta = E.from_hex(wzx)
        tau_w_zeta_omega = E.from_hex(wzox)

        zeta_a = int.from_bytes(scalars[0], 'little')
        zeta_b = int.from_bytes(scalars[1], 'little')
        zeta_c = int.from_bytes(scalars[2], 'little')
        zeta_sigma1 = int.from_bytes(scalars[3], 'little')
        zeta_sigma2 = int.from_bytes(scalars[4], 'little')
        zeta_omega = int.from_bytes(scalars[5], 'little')

        return Proof(
            tau_a, tau_b, tau_c, tau_z,
            tau_t_lo, tau_t_mid, tau_t_hi,
            tau_w_zeta, tau_w_zeta_omega,
            zeta_a, zeta_b, zeta_c, zeta_sigma1, zeta_sigma2, zeta_omega
        )

    def to_hex(self) -> str:
        """Return hex representation of the Proof"""
        points_hex = (
            self.tau_a.to_hex() +
            self.tau_b.to_hex() +
            self.tau_c.to_hex() +
            self.tau_z.to_hex() +
            self.tau_t_lo.to_hex() +
            self.tau_t_mid.to_hex() +
            self.tau_t_hi.to_hex() +
            self.tau_W_zeta.to_hex() +
            self.tau_W_zeta_omega.to_hex()
        )

        scalar_hex = (
            self.zeta_a.to_bytes(32, 'little') +
            self.zeta_b.to_bytes(32, 'little') +
            self.zeta_c.to_bytes(32, 'little') +
            self.zeta_sigma1.to_bytes(32, 'little') +
            self.zeta_sigma2.to_bytes(32, 'little') +
            self.zeta_omega.to_bytes(32, 'little')
        ).hex()

        return points_hex + scalar_hex