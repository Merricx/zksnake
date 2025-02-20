from ..arithmetization.plonkish import Plonkish
from ..ecc import EllipticCurve
from ..transcript import FiatShamirTranscript
from ..utils import Timer, batch_modinv, get_random_int
from ..polynomial import (
    PolynomialRing,
    add_over_evaluation_domain,
    barycentric_eval,
    evaluate_vanishing_polynomial,
    fft,
    get_nth_root_of_unity,
    ifft,
    mul_over_evaluation_domain,
    mul_over_fft,
    get_all_root_of_unity,
)
from .serialization import ProvingKey, VerifyingKey, Proof


class Plonk:
    """
    PlonK proof system (https://eprint.iacr.org/2019/953.pdf).

    The implementation follows the original version of the paper (vanilla PlonK).
    """

    def __init__(self, constraints: Plonkish, curve: str = "BN254"):
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.constraints = constraints
        self.G1_tau = None
        self.G2_tau = None
        self.label = "PlonK"

        self.proving_key = None
        self.verifying_key = None
        self._roots = []

    def setup(self, g1_tau=None, g2_tau=None):
        """Universal trusted setup to generate `ProvingKey` and `VerifyingKey`.

        Optionally, `g1_tau` and `g2_tau` can be provided to reuse the trusted setup
        from other sources
        """

        if not g1_tau:
            tau = get_random_int(self.order - 1)
            power_of_tau = [
                pow(tau, i, self.order) for i in range(self.constraints.length + 6)
            ]
            self.G1_tau = self.E.batch_mul(self.E.G1(), power_of_tau)
            self.G2_tau = self.E.G2() * tau
        else:
            assert (
                len(self.G1_tau) < self.constraints.length + 6
            ), "Constraints are too big for the given g1_tau"
            self.G1_tau = g1_tau
            self.G2_tau = g2_tau

        roots = get_all_root_of_unity(self.constraints.length, self.order)

        n = self.constraints.length
        k1 = 2
        k2 = 3

        id1 = roots
        id2 = [k1 * root % self.order for root in roots]
        id3 = [k2 * root % self.order for root in roots]
        ids = list(id1 + id2 + id3)
        permutation = self.constraints.permutation

        sigma1 = [ids[permutation[i]] for i in range(n)]
        sigma2 = [ids[permutation[i + n]] for i in range(n)]
        sigma3 = [ids[permutation[i + 2 * n]] for i in range(n)]

        # selector polynomials
        QL = PolynomialRing(ifft(self.constraints.qL, self.order), self.order)
        QR = PolynomialRing(ifft(self.constraints.qR, self.order), self.order)
        QO = PolynomialRing(ifft(self.constraints.qO, self.order), self.order)
        QM = PolynomialRing(ifft(self.constraints.qM, self.order), self.order)
        QC = PolynomialRing(ifft(self.constraints.qC, self.order), self.order)

        # permutation polynomials
        S1 = PolynomialRing(ifft(sigma1, self.order), self.order)
        S2 = PolynomialRing(ifft(sigma2, self.order), self.order)
        S3 = PolynomialRing(ifft(sigma3, self.order), self.order)

        selector_evaluations = {
            "L": fft(QL.coeffs(), self.order, n * 4),
            "R": fft(QR.coeffs(), self.order, n * 4),
            "O": fft(QO.coeffs(), self.order, n * 4),
            "M": fft(QM.coeffs(), self.order, n * 4),
            "C": fft(QC.coeffs(), self.order, n * 4),
        }

        selector_poly = {
            "L": QL,
            "R": QR,
            "O": QO,
            "M": QM,
            "C": QC,
        }

        sigma_permutation_poly = [
            S1,
            S2,
            S3,
        ]

        id1_poly = PolynomialRing(ifft(id1, self.order), self.order)
        id2_poly = PolynomialRing(ifft(id2, self.order), self.order)
        id3_poly = PolynomialRing(ifft(id3, self.order), self.order)

        identity_permutation_poly = [id1_poly, id2_poly, id3_poly]

        tau_QL = self.E.multiexp(self.G1_tau, QL.coeffs())
        tau_QR = self.E.multiexp(self.G1_tau, QR.coeffs())
        tau_QO = self.E.multiexp(self.G1_tau, QO.coeffs())
        tau_QM = self.E.multiexp(self.G1_tau, QM.coeffs())
        tau_QC = self.E.multiexp(self.G1_tau, QC.coeffs())
        tau_sigma1 = self.E.multiexp(self.G1_tau, S1.coeffs())
        tau_sigma2 = self.E.multiexp(self.G1_tau, S2.coeffs())
        tau_sigma3 = self.E.multiexp(self.G1_tau, S3.coeffs())

        tau_selector = {
            "L": tau_QL,
            "R": tau_QR,
            "O": tau_QO,
            "M": tau_QM,
            "C": tau_QC,
        }

        tau_permutation = [tau_sigma1, tau_sigma2, tau_sigma3]

        L1 = PolynomialRing(ifft([1] + [0] * (n - 1), self.order), self.order)
        lagrange_evals = fft(L1.coeffs(), self.order, n * 4)

        pk = ProvingKey(
            n,
            self.G1_tau,
            selector_poly,
            selector_evaluations,
            sigma_permutation_poly,
            identity_permutation_poly,
            tau_selector,
            tau_permutation,
            lagrange_evals,
            self.E.name,
        )

        vk = VerifyingKey(n, self.G2_tau, tau_selector, tau_permutation, self.E.name)

        self.proving_key = pk
        self.verifying_key = vk
        self._roots = roots

    def prove(self, public_witness: dict, private_witness: list):
        """
        Prove statement from Plonkish constraints
        by providing public and private witness
        """
        assert self.proving_key, "ProvingKey has not been generated"
        n = self.proving_key.n

        if not self._roots:
            self._roots = get_all_root_of_unity(n, self.order)

        a = private_witness[::3] + [0] * (n - len(private_witness[::3]))
        b = private_witness[1::3] + [0] * (n - len(private_witness[1::3]))
        c = private_witness[2::3] + [0] * (n - len(private_witness[2::3]))

        full_public_witness = [0] * (n)
        for k, v in public_witness.items():
            full_public_witness[k] = v

        transcript = FiatShamirTranscript()

        # vanishing polynomial X^n - 1
        Zh = PolynomialRing([-1 % self.order] + [0] * (n - 1) + [1], self.order)

        selector_poly = self.proving_key.selector_poly
        selector_eval = self.proving_key.selector_eval

        id1, id2, id3 = self.proving_key.identity_poly
        sigma1, sigma2, sigma3 = self.proving_key.permutation_poly

        tau_QL = self.proving_key.tau_selector_poly["L"]
        tau_QR = self.proving_key.tau_selector_poly["R"]
        tau_QO = self.proving_key.tau_selector_poly["O"]
        tau_QM = self.proving_key.tau_selector_poly["M"]
        tau_QC = self.proving_key.tau_selector_poly["C"]
        tau_sigma1 = self.proving_key.tau_permutation_poly[0]
        tau_sigma2 = self.proving_key.tau_permutation_poly[1]
        tau_sigma3 = self.proving_key.tau_permutation_poly[2]

        transcript.append(tau_QL)
        transcript.append(tau_QR)
        transcript.append(tau_QO)
        transcript.append(tau_QM)
        transcript.append(tau_QC)
        transcript.append(tau_sigma1)
        transcript.append(tau_sigma2)
        transcript.append(tau_sigma3)

        for _, v in public_witness.items():
            transcript.append(v)

        #########################################################################################
        # ROUND 1
        #
        # Compute wire polynomials A(x), B(x), C(x) with randomness (b1, b2, b3, b4, b5, b6)
        # Additionally, compute G = (A * QL) + (B * QR) + (A * B * QM) + (C * QO) + QC + PI
        # to be used later in round 3
        #########################################################################################

        # compute wire polynomials A(x), B(x), C(x), and public input PI(x)
        A = PolynomialRing(ifft(a, self.order), self.order)
        B = PolynomialRing(ifft(b, self.order), self.order)
        C = PolynomialRing(ifft(c, self.order), self.order)
        PI = PolynomialRing(ifft(full_public_witness, self.order), self.order)

        zero_pad = [0] * (n - 2)
        blinding_a = PolynomialRing(
            [get_random_int(self.order - 1) for _ in range(2)] + zero_pad,
            self.order,
        )
        blinding_b = PolynomialRing(
            [get_random_int(self.order - 1) for _ in range(2)] + zero_pad,
            self.order,
        )
        blinding_c = PolynomialRing(
            [get_random_int(self.order - 1) for _ in range(2)] + zero_pad,
            self.order,
        )

        # wire polynomials with blinding factors
        A = A + blinding_a.multiply_by_vanishing_poly()
        B = B + blinding_b.multiply_by_vanishing_poly()
        C = C + blinding_c.multiply_by_vanishing_poly()

        # evaluation form of wire polynomials
        a_eval = fft(A.coeffs(), self.order, n * 4)
        b_eval = fft(B.coeffs(), self.order, n * 4)
        c_eval = fft(C.coeffs(), self.order, n * 4)
        pi_eval = fft(PI.coeffs(), self.order, n * 4)

        a_ql = mul_over_evaluation_domain(n * 4, a_eval, selector_eval["L"], self.order)
        b_qr = mul_over_evaluation_domain(n * 4, b_eval, selector_eval["R"], self.order)
        c_qo = mul_over_evaluation_domain(n * 4, c_eval, selector_eval["O"], self.order)
        ab = mul_over_evaluation_domain(n * 4, a_eval, b_eval, self.order)
        ab_qm = mul_over_evaluation_domain(n * 4, ab, selector_eval["M"], self.order)

        # G = (A * QL) + (B * QR) + (A * B * QM) + (C * QO) + QC + PI
        g_eval = add_over_evaluation_domain(
            n * 4,
            [a_ql, b_qr, c_qo, ab_qm, selector_eval["C"], pi_eval],
            self.order,
        )
        G = PolynomialRing(ifft(g_eval, self.order), self.order, n)

        tau_a = self.E.multiexp(self.proving_key.tau_g1, A.coeffs())
        tau_b = self.E.multiexp(self.proving_key.tau_g1, B.coeffs())
        tau_c = self.E.multiexp(self.proving_key.tau_g1, C.coeffs())

        transcript.append(tau_a)
        transcript.append(tau_b)
        transcript.append(tau_c)

        #########################################################################################
        # ROUND 2
        #
        # Compute permutation polynomial z(X) with randomness (b7, b8, b9) and challenge (beta, gamma)
        #########################################################################################

        beta = transcript.get_challenge_scalar() % self.order
        transcript.reset()
        transcript.append(beta)
        gamma = transcript.get_challenge_scalar() % self.order

        zero_pad = [0] * (n - 3)
        blinding_permutation = PolynomialRing(
            [get_random_int(self.order - 1) for _ in range(3)] + zero_pad,
            self.order,
        )

        a_id = fft((A + id1 * beta + gamma).coeffs(), self.order, n * 4)
        b_id = fft((B + id2 * beta + gamma).coeffs(), self.order, n * 4)
        c_id = fft((C + id3 * beta + gamma).coeffs(), self.order, n * 4)

        ab_id = mul_over_evaluation_domain(n * 4, a_id, b_id, self.order)
        eval_nom_poly = mul_over_evaluation_domain(n * 4, ab_id, c_id, self.order)
        nom_poly = PolynomialRing(ifft(eval_nom_poly, self.order), self.order)

        a_sigma = fft((A + sigma1 * beta + gamma).coeffs(), self.order, n * 4)
        b_sigma = fft((B + sigma2 * beta + gamma).coeffs(), self.order, n * 4)
        c_sigma = fft((C + sigma3 * beta + gamma).coeffs(), self.order, n * 4)

        ab_sigma = mul_over_evaluation_domain(n * 4, a_sigma, b_sigma, self.order)
        eval_denom_poly = mul_over_evaluation_domain(
            n * 4, ab_sigma, c_sigma, self.order
        )
        denom_poly = PolynomialRing(ifft(eval_denom_poly, self.order), self.order)

        nom_inv_denom = batch_modinv(
            [eval_denom_poly[i] for i in range(0, len(eval_denom_poly), 4)],
            self.order,
        )

        accumulator = [1]
        for i in range(n):
            accumulator += [
                accumulator[-1] * eval_nom_poly[i * 4] * nom_inv_denom[i] % self.order
            ]

        assert accumulator.pop() == 1, "Copy constraints are not satisfied"

        acc_poly = PolynomialRing(ifft(accumulator, self.order), self.order)

        Z = blinding_permutation.multiply_by_vanishing_poly() + acc_poly
        tau_z = self.E.multiexp(self.proving_key.tau_g1, Z.coeffs())

        transcript.reset()
        transcript.append(beta)
        transcript.append(gamma)
        transcript.append(tau_z)

        #########################################################################################
        # ROUND 3
        #
        # Compute quotient polynomial T(X) with randomness (b10, b11) and challenge alpha
        #########################################################################################

        alpha = transcript.get_challenge_scalar() % self.order

        Z_omega = PolynomialRing(
            [
                coeff * self._roots[i % n] % self.order
                for i, coeff in enumerate(Z.coeffs())
            ],
            self.order,
        )

        nom_poly_Z = mul_over_fft(n, nom_poly, Z, self.order)
        denom_poly_Z_omega = mul_over_fft(n, denom_poly, Z_omega, self.order)

        z_1_eval = fft((Z - 1).coeffs(), self.order, n * 4)
        z_1_l1_eval = mul_over_evaluation_domain(
            n * 4, z_1_eval, self.proving_key.lagrange_evals, self.order
        )
        Z_1_L1 = PolynomialRing(ifft(z_1_l1_eval, self.order), self.order)

        T, remainder = (
            G
            + (nom_poly_Z - denom_poly_Z_omega) * alpha
            + Z_1_L1 * pow(alpha, 2, self.order)
        ).divide_by_vanishing_poly()

        assert remainder.is_zero()

        t_coeff = T.coeffs()
        T_lo = PolynomialRing(t_coeff[:n], self.order)
        T_mid = PolynomialRing(t_coeff[n : 2 * n], self.order)
        T_hi = PolynomialRing(t_coeff[2 * n :], self.order)

        X_n = PolynomialRing([0] * (n) + [1], self.order)

        blindings = [get_random_int(self.order - 1) for _ in range(2)]

        T_lo = T_lo + X_n * blindings[0]
        T_mid = T_mid - blindings[0] + X_n * blindings[1]
        T_hi = T_hi - blindings[1]

        tau_T_lo = self.E.multiexp(self.proving_key.tau_g1, T_lo.coeffs())
        tau_T_mid = self.E.multiexp(self.proving_key.tau_g1, T_mid.coeffs())
        tau_T_hi = self.E.multiexp(self.proving_key.tau_g1, T_hi.coeffs())

        transcript.reset()
        transcript.append(alpha)
        transcript.append(tau_T_lo)
        transcript.append(tau_T_mid)
        transcript.append(tau_T_hi)

        #########################################################################################
        # ROUND 4
        #
        # Compute opening evaluation A(x), B(x), C(x), sigma1(x), sigma2(x), Z_omega(x)
        # and linearization polynomial R(x) at zeta
        #########################################################################################

        zeta = transcript.get_challenge_scalar() % self.order

        zeta_A = A(zeta)
        zeta_B = B(zeta)
        zeta_C = C(zeta)
        zeta_sigma1 = sigma1(zeta)
        zeta_sigma2 = sigma2(zeta)
        zeta_Z_omega = Z_omega(zeta)

        L1_zeta = barycentric_eval(n, {0: 1}, zeta, self.order)

        k1 = 2
        k2 = 3
        R = (
            (
                selector_poly["L"] * zeta_A
                + selector_poly["R"] * zeta_B
                + selector_poly["O"] * zeta_C
                + selector_poly["M"] * zeta_A * zeta_B
                + selector_poly["C"]
                + PI(zeta)
            )
            + alpha
            * (
                (zeta_A + beta * zeta + gamma)
                * (zeta_B + beta * k1 * zeta + gamma)
                * (zeta_C + beta * k2 * zeta + gamma)
                * Z
                - (zeta_A + beta * zeta_sigma1 + gamma)
                * (zeta_B + beta * zeta_sigma2 + gamma)
                * (sigma3 * beta + zeta_C + gamma)
                * zeta_Z_omega
            )
            + pow(alpha, 2, self.order) * ((Z - 1) * L1_zeta)
            - (
                (
                    T_lo
                    + pow(zeta, n, self.order) * T_mid
                    + T_hi * pow(zeta, n * 2, self.order)
                )
                * Zh(zeta)
            )
        )

        transcript.reset()
        transcript.append(zeta)
        transcript.append(zeta_A)
        transcript.append(zeta_B)
        transcript.append(zeta_C)
        transcript.append(zeta_sigma1)
        transcript.append(zeta_sigma2)
        transcript.append(zeta_Z_omega)

        #########################################################################################
        # ROUND 5
        #
        # Compute opening proof polynomial W(x) with challenge v
        #########################################################################################

        v = transcript.get_challenge_scalar() % self.order

        W_zeta = (
            R
            + (A - zeta_A) * v
            + (B - zeta_B) * pow(v, 2, self.order)
            + (C - zeta_C) * pow(v, 3, self.order)
            + (sigma1 - zeta_sigma1) * pow(v, 4, self.order)
            + (sigma2 - zeta_sigma2) * pow(v, 5, self.order)
        )
        divisor_W_zeta = PolynomialRing([-zeta % self.order, 1], self.order)

        W_zeta, remainder = W_zeta / divisor_W_zeta

        assert remainder.is_zero()

        divisor_W_zeta_omega = PolynomialRing(
            [-(zeta * self._roots[1]) % self.order, 1], self.order
        )
        W_zeta_omega, remainder = (Z - zeta_Z_omega) / divisor_W_zeta_omega

        assert remainder.is_zero()

        tau_W_zeta = self.E.multiexp(self.proving_key.tau_g1, W_zeta.coeffs())
        tau_W_zeta_omega = self.E.multiexp(
            self.proving_key.tau_g1, W_zeta_omega.coeffs()
        )

        return Proof(
            tau_a,
            tau_b,
            tau_c,
            tau_z,
            tau_T_lo,
            tau_T_mid,
            tau_T_hi,
            tau_W_zeta,
            tau_W_zeta_omega,
            zeta_A,
            zeta_B,
            zeta_C,
            zeta_sigma1,
            zeta_sigma2,
            zeta_Z_omega,
        )

    def __recompute_challenges(self, proof: Proof, public_input: dict):

        transcript = FiatShamirTranscript()

        tau_QL = self.verifying_key.tau_selector_poly["L"]
        tau_QR = self.verifying_key.tau_selector_poly["R"]
        tau_QO = self.verifying_key.tau_selector_poly["O"]
        tau_QM = self.verifying_key.tau_selector_poly["M"]
        tau_QC = self.verifying_key.tau_selector_poly["C"]
        tau_sigma1 = self.verifying_key.tau_permutation_poly[0]
        tau_sigma2 = self.verifying_key.tau_permutation_poly[1]
        tau_sigma3 = self.verifying_key.tau_permutation_poly[2]

        transcript.append(tau_QL)
        transcript.append(tau_QR)
        transcript.append(tau_QO)
        transcript.append(tau_QM)
        transcript.append(tau_QC)
        transcript.append(tau_sigma1)
        transcript.append(tau_sigma2)
        transcript.append(tau_sigma3)

        for _, v in public_input.items():
            transcript.append(v)

        transcript.append(proof.tau_a)
        transcript.append(proof.tau_b)
        transcript.append(proof.tau_c)
        beta = transcript.get_challenge_scalar() % self.order
        transcript.reset()
        transcript.append(beta)
        gamma = transcript.get_challenge_scalar() % self.order

        transcript.reset()
        transcript.append(beta)
        transcript.append(gamma)
        transcript.append(proof.tau_z)
        alpha = transcript.get_challenge_scalar() % self.order

        transcript.reset()
        transcript.append(alpha)
        transcript.append(proof.tau_t_lo)
        transcript.append(proof.tau_t_mid)
        transcript.append(proof.tau_t_hi)
        zeta = transcript.get_challenge_scalar() % self.order

        transcript.reset()
        transcript.append(zeta)
        transcript.append(proof.zeta_a)
        transcript.append(proof.zeta_b)
        transcript.append(proof.zeta_c)
        transcript.append(proof.zeta_sigma1)
        transcript.append(proof.zeta_sigma2)
        transcript.append(proof.zeta_omega)
        v = transcript.get_challenge_scalar() % self.order

        transcript.reset()
        transcript.append(proof.tau_W_zeta)
        transcript.append(proof.tau_W_zeta_omega)
        u = transcript.get_challenge_scalar() % self.order

        return beta, gamma, alpha, zeta, v, u

    def verify(self, proof: Proof, public_input: dict):
        """
        Verify proof by providing public witness
        """
        assert self.verifying_key, "VerifyingKey has not been generated"

        n = self.verifying_key.n

        tau_QL = self.verifying_key.tau_selector_poly["L"]
        tau_QR = self.verifying_key.tau_selector_poly["R"]
        tau_QO = self.verifying_key.tau_selector_poly["O"]
        tau_QM = self.verifying_key.tau_selector_poly["M"]
        tau_QC = self.verifying_key.tau_selector_poly["C"]
        tau_sigma1 = self.verifying_key.tau_permutation_poly[0]
        tau_sigma2 = self.verifying_key.tau_permutation_poly[1]
        tau_sigma3 = self.verifying_key.tau_permutation_poly[2]

        beta, gamma, alpha, zeta, v, u = self.__recompute_challenges(
            proof, public_input
        )

        k1 = 2
        k2 = 3

        if self._roots:
            omega = self._roots[1]
        else:
            omega = get_nth_root_of_unity(n, 1, self.order)

        Zh_zeta = evaluate_vanishing_polynomial(n, zeta, self.order)
        L1_zeta = barycentric_eval(n, {0: 1}, zeta, self.order)
        PI_zeta = barycentric_eval(n, public_input, zeta, self.order)

        r0 = (
            PI_zeta
            - L1_zeta * pow(alpha, 2, self.order)
            - (proof.zeta_a + beta * proof.zeta_sigma1 + gamma)
            * (proof.zeta_b + beta * proof.zeta_sigma2 + gamma)
            * (proof.zeta_c + gamma)
            * proof.zeta_omega
            * alpha
        ) % self.order

        tau_D = (
            (proof.zeta_a * proof.zeta_b * tau_QM)
            + (proof.zeta_a * tau_QL)
            + (proof.zeta_b * tau_QR)
            + (proof.zeta_c * tau_QO)
            + tau_QC
            + (
                (proof.zeta_a + beta * zeta + gamma)
                * (proof.zeta_b + beta * k1 * zeta + gamma)
                * (proof.zeta_c + beta * k2 * zeta + gamma)
                * alpha
                + L1_zeta * pow(alpha, 2, self.order)
                + u
            )
            * proof.tau_z
            - (
                (proof.zeta_a + beta * proof.zeta_sigma1 + gamma)
                * (proof.zeta_b + beta * proof.zeta_sigma2 + gamma)
                * alpha
                * beta
                * proof.zeta_omega
            )
            * tau_sigma3
            - Zh_zeta
            * (
                proof.tau_t_lo
                + pow(zeta, n, self.order) * proof.tau_t_mid
                + pow(zeta, n * 2, self.order) * proof.tau_t_hi
            )
        )

        tau_F = (
            tau_D
            + proof.tau_a * v
            + proof.tau_b * pow(v, 2, self.order)
            + proof.tau_c * pow(v, 3, self.order)
            + tau_sigma1 * pow(v, 4, self.order)
            + tau_sigma2 * pow(v, 5, self.order)
        )

        tau_E = (
            (
                -r0
                + v * proof.zeta_a
                + pow(v, 2, self.order) * proof.zeta_b
                + pow(v, 3, self.order) * proof.zeta_c
                + pow(v, 4, self.order) * proof.zeta_sigma1
                + pow(v, 5, self.order) * proof.zeta_sigma2
                + u * proof.zeta_omega
            )
            % self.order
        ) * self.E.G1()

        lhs = self.E.pairing(
            proof.tau_W_zeta + u * proof.tau_W_zeta_omega, self.verifying_key.tau_g2
        )

        rhs = self.E.pairing(
            zeta * proof.tau_W_zeta
            + (u * zeta * omega) * proof.tau_W_zeta_omega
            + tau_F
            - tau_E,
            self.E.G2(),
        )

        return lhs == rhs
