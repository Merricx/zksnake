"""Trusted setup module of Groth16 protocol"""

from ..qap import QAP
from ..polynomial import PolynomialRing
from ..ecc import EllipticCurve
from .prover import ProvingKey
from .verifier import VerifyingKey
from ..utils import get_random_int


class Setup:

    def __init__(self, qap: QAP, curve: str = "BN128"):
        """
        Trusted setup object

        Args:
            qap: QAP to be set up from
            curve: `BN128` or `BLS12_381`
        """
        self.qap = qap
        self.E = EllipticCurve(curve)
        self.order = self.E.curve.curve_order

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

        L = [
            [j * beta % self.order for j in self.qap.U[i]]
            for i in range(len(self.qap.U))
        ]
        R = [
            [j * alpha % self.order for j in self.qap.V[i]]
            for i in range(len(self.qap.V))
        ]
        O = self.qap.W

        K = []
        for i in range(len(O)):
            k_list = []
            for j in range(len(O[i])):
                k_list.append((L[i][j] + R[i][j] + O[i][j]) % self.order)

            poly = PolynomialRing(k_list, self.order)
            K.append(poly(tau))

        t = self.qap.T(tau)

        power_of_tau = [pow(tau, i, self.order) for i in range(self.qap.T.degree())]
        tau_G1 = [G1 * power_of_tau[i] for i in range(self.qap.T.degree())]
        tau_G2 = [G2 * power_of_tau[i] for i in range(self.qap.T.degree())]

        tau_div_delta = [
            (power_of_tau[i] * t) * inv_delta % self.order
            for i in range(self.qap.T.degree() - 1)
        ]

        target_G1 = [G1 * i for i in tau_div_delta]

        k_gamma = [k * inv_gamma for k in K[: self.qap.n_public]]
        k_delta = [k * inv_delta for k in K[self.qap.n_public :]]

        k_gamma_G1 = [G1 * k for k in k_gamma]
        k_delta_G1 = [G1 * k for k in k_delta]

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


class MPC:
    def __init__(self, qap: QAP, curve: str = "BN128"):
        """
        MPC to perform trusted ceremony

        Args:
            qap: QAP to be set up from
            curve: `BN128` or `BLS12_381`
        """
        self.qap = qap
        self.E = EllipticCurve(curve)
        self.order = self.E.curve.curve_order

    def generate(
        self, pk: ProvingKey, vk: VerifyingKey
    ) -> tuple[ProvingKey, VerifyingKey]:
        pass
