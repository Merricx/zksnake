
from ..arithmetization.plonkish import Plonkish
from ..ecc import EllipticCurve
from ..utils import get_random_int
from ..polynomial import PolynomialRing, get_all_root_of_unity, get_nth_root_of_unity, ifft
from .prover import ProvingKey
from .verifier import VerifyingKey

class Setup():

    def __init__(self, constraints: Plonkish, G1_tau = None, G2_tau = None, curve: str = "BN254"):
        """
        Trusted setup object

        Args:
            r1cs: R1CS to be set up from
            curve: `BN254` or `BLS12_381`
        """
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.constraints = constraints
        self.G1_tau = G1_tau
        self.G2_tau = G2_tau

    def generate(self) -> tuple[ProvingKey, VerifyingKey]:
        """Generate `ProvingKey` and `VerifyingKey`"""

        tau = get_random_int(self.order-1)
        power_of_tau = [pow(tau, i, self.order) for i in range(self.constraints.length+7)]

        if not self.G1_tau:
            self.G1_tau = self.E.batch_mul(self.E.G1(), power_of_tau)
            self.G2_tau = self.E.G2() * tau

        roots = get_all_root_of_unity(self.constraints.length, self.order)

        n = self.constraints.length
        k1 = 2
        k2 = 3

        id1 = roots
        id2 = [k1 * root % self.order for root in roots]
        id3 = [k2 * root % self.order for root in roots]
        ids = list(id1+id2+id3)
        permutation = self.constraints.permutation
        
        sigma1 = [ids[permutation[i]] for i in range(n)]
        sigma2 = [ids[permutation[i + n]] for i in range(n)]
        sigma3 = [ids[permutation[i + 2*n]] for i in range(n)]

        QL = PolynomialRing(ifft(self.constraints.qL, self.order), self.order)
        QR = PolynomialRing(ifft(self.constraints.qR, self.order), self.order)
        QO = PolynomialRing(ifft(self.constraints.qO, self.order), self.order)
        QM = PolynomialRing(ifft(self.constraints.qM, self.order), self.order)
        QC = PolynomialRing(ifft(self.constraints.qC, self.order), self.order)
        S1 = PolynomialRing(ifft(sigma1, self.order), self.order)
        S2 = PolynomialRing(ifft(sigma2, self.order), self.order)
        S3 = PolynomialRing(ifft(sigma3, self.order), self.order)

        selector_poly = {
            'L': QL,
            'R': QR,
            'O': QO,
            'M': QM,
            'C': QC,
        }

        sigma_permutation_poly = [
            S1,
            S2,
            S3,
        ]

        identity_permutation_poly = [
            PolynomialRing(ifft(id1, self.order), self.order),
            PolynomialRing(ifft(id2, self.order), self.order),
            PolynomialRing(ifft(id3, self.order), self.order),
        ]

        tau_QL = self.E.multiexp(self.G1_tau, QL.coeffs())
        tau_QR = self.E.multiexp(self.G1_tau, QR.coeffs())
        tau_QO = self.E.multiexp(self.G1_tau, QO.coeffs())
        tau_QM = self.E.multiexp(self.G1_tau, QM.coeffs())
        tau_QC = self.E.multiexp(self.G1_tau, QC.coeffs())
        tau_sigma1 = self.E.multiexp(self.G1_tau, S1.coeffs())
        tau_sigma2 = self.E.multiexp(self.G1_tau, S2.coeffs())
        tau_sigma3 = self.E.multiexp(self.G1_tau, S3.coeffs())

        tau_selector = {
            'L': tau_QL,
            'R': tau_QR,
            'O': tau_QO,
            'M': tau_QM,
            'C': tau_QC,
        }

        tau_permutation = [tau_sigma1 ,tau_sigma2, tau_sigma3]
        
        pk = ProvingKey(
            n, self.G1_tau, self.G2_tau, selector_poly, sigma_permutation_poly, identity_permutation_poly,
            tau_selector, tau_permutation,
            self.E.name
        )

        vk = VerifyingKey(n, self.G1_tau, self.G2_tau, tau_selector, tau_permutation, self.E.name)

        return pk, vk