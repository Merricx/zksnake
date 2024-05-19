"""Trusted setup module of Groth16 protocol"""

from joblib import Parallel, delayed

from ..qap import QAP
from ..ecc import EllipticCurve
from ..polynomial import (
    evaluate_vanishing_polynomial,
    evaluate_lagrange_coefficients,
)
from .prover import ProvingKey
from .verifier import VerifyingKey
from ..utils import get_random_int, get_n_jobs


class Setup:

    def __init__(self, qap: QAP, curve: str = "BN254"):
        """
        Trusted setup object

        Args:
            qap: QAP to be set up from
            curve: `BN254` or `BLS12_381`
        """
        self.qap = qap
        self.E = EllipticCurve(curve)
        self.order = self.E.order

    def generate(self) -> tuple[ProvingKey, VerifyingKey]:
        """Generate `ProvingKey` and `VerifyingKey`"""

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

        degree = self.qap.a.n_row
        n_constraint = self.qap.a.n_col

        lagrange_coeffs = evaluate_lagrange_coefficients(degree, tau, self.order)

        L = [0] * n_constraint
        R = [0] * n_constraint
        O = [0] * n_constraint

        for i, coeff in enumerate(lagrange_coeffs):
            for row, col, value in self.qap.a.triplets:
                if i == row:
                    L[col] += coeff * value
            for row, col, value in self.qap.b.triplets:
                if i == row:
                    R[col] += coeff * value
            for row, col, value in self.qap.c.triplets:
                if i == row:
                    O[col] += coeff * value

        K = [
            (L[i] * beta + R[i] * alpha + O[i]) % self.order
            for i in range(n_constraint)
        ]

        t = evaluate_vanishing_polynomial(degree, tau, self.order)

        power_of_tau = [pow(tau, i, self.order) for i in range(degree)]
        tau_G1 = self.E.batch_mul(G1, power_of_tau)
        tau_G2 = self.E.batch_mul(G2, power_of_tau)

        o = self.order
        tau_div_delta = Parallel(n_jobs=get_n_jobs())(
            delayed(lambda x: x * t * inv_delta % o)(power_of_tau[i])
            for i in range(degree - 1)
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

        return pkey, vkey
