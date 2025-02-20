from joblib import Parallel, delayed
from ..arithmetization.r1cs import R1CS

from .qap import QAP
from ..ecc import EllipticCurve
from ..polynomial import (
    evaluate_vanishing_polynomial,
    evaluate_lagrange_coefficients,
)
from .serialization import Proof, ProvingKey, VerifyingKey
from ..utils import get_random_int, get_n_jobs


class Groth16:
    """
    Groth16 proof system (https://eprint.iacr.org/2016/260.pdf)

    Args:
        r1cs: R1CS to be set up from
        curve: `BN254` or `BLS12_381`
    """

    def __init__(self, r1cs: R1CS, curve: str = "BN254"):
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.qap = QAP(self.order)
        self.qap.from_r1cs(r1cs)

        self.proving_key = None
        self.verifying_key = None

    def setup(self):
        """Trusted setup to generate `ProvingKey` and `VerifyingKey`"""

        G1 = self.E.G1()
        G2 = self.E.G2()

        # generate random toxic waste
        tau = get_random_int(self.order - 1)
        alpha = get_random_int(self.order - 1)
        beta = get_random_int(self.order - 1)
        gamma = get_random_int(self.order - 1)
        delta = get_random_int(self.order - 1)

        inv_gamma = pow(gamma, -1, self.order)
        inv_delta = pow(delta, -1, self.order)

        alpha_G1 = G1 * alpha
        beta_G1 = G1 * beta
        beta_G2 = G2 * beta
        gamma_G2 = G2 * gamma
        delta_G1 = G1 * delta
        delta_G2 = G2 * delta

        n_constraints = self.qap.a.n_row
        n_witness = self.qap.a.n_col

        lagrange_coeffs = evaluate_lagrange_coefficients(n_constraints, tau, self.order)

        L = [0] * n_witness
        R = [0] * n_witness
        O = [0] * n_witness

        for i, coeff in enumerate(lagrange_coeffs):
            multipliers = self.qap.a.triplets_map.get(i, [])
            for col, value in multipliers:
                L[col] += coeff * value

            multipliers = self.qap.b.triplets_map.get(i, [])
            for col, value in multipliers:
                R[col] += coeff * value

            multipliers = self.qap.c.triplets_map.get(i, [])
            for col, value in multipliers:
                O[col] += coeff * value

        K = [(L[i] * beta + R[i] * alpha + O[i]) % self.order for i in range(n_witness)]

        t = evaluate_vanishing_polynomial(n_constraints, tau, self.order)

        power_of_tau = [pow(tau, i, self.order) for i in range(n_constraints)]
        tau_G1 = self.E.batch_mul(G1, power_of_tau)
        tau_G2 = self.E.batch_mul(G2, power_of_tau)

        o = self.order
        tau_div_delta = Parallel(n_jobs=get_n_jobs())(
            delayed(lambda x: x * t * inv_delta % o)(power_of_tau[i])
            for i in range(n_constraints)
        )

        target_G1 = self.E.batch_mul(G1, tau_div_delta)

        inv_gamma_G1 = G1 * inv_gamma
        inv_delta_G1 = G1 * inv_delta

        k_gamma_G1 = self.E.batch_mul(inv_gamma_G1, K[: self.qap.n_public])
        k_delta_G1 = self.E.batch_mul(inv_delta_G1, K[self.qap.n_public :])

        pkey = ProvingKey(
            alpha_G1,
            beta_G1,
            beta_G2,
            delta_G1,
            delta_G2,
            tau_G1,
            tau_G2,
            target_G1,
            k_delta_G1,
        )
        vkey = VerifyingKey(alpha_G1, beta_G2, gamma_G2, delta_G2, k_gamma_G1)

        self.proving_key = pkey
        self.verifying_key = vkey

    def prove(self, public_witness: list, private_witness: list) -> Proof:
        """
        Prove statement from R1CS by providing public and private witness
        """
        assert self.proving_key, "ProvingKey has not been generated"

        assert len(self.proving_key.kdelta_1) == len(
            private_witness
        ), "Length of kdelta_1 and private_witness must be equal"

        r = get_random_int(self.order - 1)
        s = get_random_int(self.order - 1)

        try:
            U, V, _, H = self.qap.evaluate_witness(public_witness + private_witness)
        except ValueError as exc:
            raise ValueError("Failed to evaluate with the given witness") from exc

        A = (
            self.E.multiexp(self.proving_key.tau_1, U.coeffs())
            + self.proving_key.alpha_1
            + (self.proving_key.delta_1 * r)
        )
        B1 = (
            self.E.multiexp(self.proving_key.tau_1, V.coeffs())
            + self.proving_key.beta_1
            + (self.proving_key.delta_1 * s)
        )
        B2 = (
            self.E.multiexp(self.proving_key.tau_2, V.coeffs())
            + self.proving_key.beta_2
            + (self.proving_key.delta_2 * s)
        )
        HZ = self.E.multiexp(self.proving_key.target_1, H.coeffs())

        if len(private_witness) > 0:
            sum_delta_witness = self.E.multiexp(
                self.proving_key.kdelta_1, private_witness
            )
        else:  # all inputs are public
            sum_delta_witness = self.E.G1() * 0

        C = (
            HZ
            + sum_delta_witness
            + (A * s)
            + (B1 * r)
            + (-self.proving_key.delta_1 * (r * s % self.order))
        )

        return Proof(A, B2, C)

    def verify(self, proof: Proof, public_witness: list) -> bool:
        """
        Verify proof by providing public witness
        """
        assert self.verifying_key, "VerifyingKey has not been generated"
        assert len(self.verifying_key.ic) == len(
            public_witness
        ), "Length of IC and public_witness must be equal"

        sum_gamma_witness = self.E.multiexp(self.verifying_key.ic, public_witness)

        # e(A, B) == e(alpha, beta) + e(sum_gamma_witness, gamma) + e(C, delta)
        return self.E.pairing(proof.A, proof.B) == self.E.multi_pairing(
            [self.verifying_key.alpha_1, sum_gamma_witness, proof.C],
            [
                self.verifying_key.beta_2,
                self.verifying_key.gamma_2,
                self.verifying_key.delta_2,
            ],
        )
