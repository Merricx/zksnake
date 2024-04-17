import random
from ..qap import QAP
from ..polynomial import PolynomialRing
from ..ecc import EllipticCurve
from .prover import ProvingKey
from .verifier import VerifyingKey

class Setup:

    def __init__(self, qap: QAP, curve: str='BN128'):
        """
        Trusted setup object

        Args:
            qap: QAP to be set up from
            curve: `BN128` or `BLS12_381`
        """
        self.qap = qap
        self.E = EllipticCurve(curve)
        self.order = self.E.curve.curve_order

    def __urandom(self):
        rand = random.SystemRandom()
        return rand.randint(1, self.order - 1)

    def generate(self) -> tuple[ProvingKey, VerifyingKey]:
        """Generate `ProvingKey` and `VerifyingKey`"""

        G1 = self.E.G1()
        G2 = self.E.G2()

        # generate random toxic waste
        tau = self.__urandom()
        alpha = self.__urandom()
        beta = self.__urandom()
        gamma = self.__urandom()
        delta = self.__urandom()

        alpha_G1 = G1 * alpha
        beta_G1 = G1 * beta
        beta_G2 = G2 * beta
        gamma_G2 = G2 * gamma
        delta_G1 = G1 * delta
        delta_G2 = G2 * delta

        L = [[j * alpha % self.order for j in self.qap.U[i]] for i in range(len(self.qap.U))]
        R = [[j * beta % self.order for j in self.qap.V[i]] for i in range(len(self.qap.V))]
        O = self.qap.W

        K = []
        for i in range(len(O)):
            k_list = []
            for j in range(len(O[i])):
                k_list.append((L[i][j] + R[i][j] + O[i][j]) % self.order)

            poly = PolynomialRing(k_list, self.order)
            K.append(poly(tau))

        t = self.qap.T(tau)
        tau_G1 = [G1 * pow(tau, i, self.order) for i in range(self.qap.T.degree())]
        tau_G2 = [G2 * pow(tau, i, self.order) for i in range(self.qap.T.degree())]

        tau_div_delta = [
            (pow(tau, i, self.order) * t) * 
            pow(delta, -1, self.order) %self.order
            for i in range(self.qap.T.degree()-1)
        ]
        
        target_G1 = [G1 * i for i in tau_div_delta]

        k_gamma = [k * pow(gamma, -1, self.order) for k in K[:self.qap.n_public]]
        k_delta = [k * pow(delta, -1, self.order) for k in K[self.qap.n_public:]]

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
            k_delta_G1
        )
        vkey = VerifyingKey(
            alpha_G1,
            beta_G2,
            gamma_G2,
            delta_G2,
            k_gamma_G1
        )

        return pkey, vkey