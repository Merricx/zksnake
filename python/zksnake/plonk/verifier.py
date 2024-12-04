from ..ecc import EllipticCurve
from .prover import Proof
from ..transcript import FiatShamirTranscript
from ..polynomial import PolynomialRing, evaluate_vanishing_polynomial, get_nth_root_of_unity, ifft

class VerifyingKey:

    def __init__(
        self,
        n,
        tau_G1,
        tau_G2,
        tau_selector_poly,
        tau_permutation_poly,
        curve: str = "BN254"
    ):
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.n = n
        self.tau_g1 = tau_G1
        self.tau_g2 = tau_G2
        self.tau_selector_poly = tau_selector_poly
        self.tau_permutation_poly = tau_permutation_poly

        
class Verifier:

    def __init__(self, key: VerifyingKey, label: str = 'PlonK'):
        self.key = key
        self.n = key.n
        self.E = key.E
        self.order = key.order
        self.label = label

    def __recompute_challenges(self, proof: Proof):

        transcript = FiatShamirTranscript(self.label.encode())

        tau_QL = self.key.tau_selector_poly['L']
        tau_QR = self.key.tau_selector_poly['R']
        tau_QO = self.key.tau_selector_poly['O']
        tau_QM = self.key.tau_selector_poly['M']
        tau_QC = self.key.tau_selector_poly['C']
        tau_sigma1 = self.key.tau_permutation_poly[0]
        tau_sigma2 = self.key.tau_permutation_poly[1]
        tau_sigma3 = self.key.tau_permutation_poly[2]

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
        transcript.append(proof.tau_a)
        transcript.append(proof.tau_b)
        transcript.append(proof.tau_c)
        transcript.append(0)
        beta = transcript.get_challenge_scalar() % self.order
        transcript.append(1)
        gamma = transcript.get_challenge_scalar() % self.order
        transcript.append(proof.tau_z)
        alpha = transcript.get_challenge_scalar() % self.order
        transcript.append(proof.tau_t_lo)
        transcript.append(proof.tau_t_mid)
        transcript.append(proof.tau_t_hi)
        zeta = transcript.get_challenge_scalar() % self.order
        transcript.append(proof.zeta_a)
        transcript.append(proof.zeta_b)
        transcript.append(proof.zeta_c)
        transcript.append(proof.zeta_sigma1)
        transcript.append(proof.zeta_sigma2)
        transcript.append(proof.zeta_omega)
        v = transcript.get_challenge_scalar() % self.order
        transcript.append(proof.tau_W_zeta)
        transcript.append(proof.tau_W_zeta_omega)
        u = transcript.get_challenge_scalar() % self.order

        return beta, gamma, alpha, zeta, v, u
    
    def verify(self, proof: Proof, public_input: list):
        
        public_input += [0]*(self.n - len(public_input))

        tau_QL = self.key.tau_selector_poly['L']
        tau_QR = self.key.tau_selector_poly['R']
        tau_QO = self.key.tau_selector_poly['O']
        tau_QM = self.key.tau_selector_poly['M']
        tau_QC = self.key.tau_selector_poly['C']
        tau_sigma1 = self.key.tau_permutation_poly[0]
        tau_sigma2 = self.key.tau_permutation_poly[1]
        tau_sigma3 = self.key.tau_permutation_poly[2]
        
        beta, gamma, alpha, zeta, v, u = self.__recompute_challenges(proof)

        k1 = 2
        k2 = 3
        
        L1 = PolynomialRing(ifft([1] + [0]*(self.n-1), self.order), self.order)
        PI = PolynomialRing(ifft(public_input, self.order), self.order)

        omega = get_nth_root_of_unity(self.n, 1, self.order)

        Zh_zeta = evaluate_vanishing_polynomial(self.n, zeta, self.order)
        L1_zeta = L1(zeta)
        PI_zeta = PI(zeta)

        r0 = (
            PI_zeta - L1_zeta * pow(alpha, 2, self.order) -
            (proof.zeta_a + beta * proof.zeta_sigma1 + gamma) *
            (proof.zeta_b + beta * proof.zeta_sigma2 + gamma) *
            (proof.zeta_c + gamma) * proof.zeta_omega * alpha
        ) % self.order

        tau_D = (
            (proof.zeta_a * proof.zeta_b * tau_QM) +
            (proof.zeta_a * tau_QL) +
            (proof.zeta_b * tau_QR) +
            (proof.zeta_c * tau_QO) + tau_QC +
            
            ((proof.zeta_a + beta * zeta + gamma)*
             (proof.zeta_b + beta * k1 * zeta + gamma) *
             (proof.zeta_c + beta * k2 * zeta + gamma) *
             alpha + L1_zeta * pow(alpha, 2, self.order) + u
            ) * proof.tau_z -
            
            (
                (proof.zeta_a + beta * proof.zeta_sigma1 + gamma) *
                (proof.zeta_b + beta * proof.zeta_sigma2 + gamma) *
                alpha * beta * proof.zeta_omega
            ) * tau_sigma3 -
            
            Zh_zeta * (
                proof.tau_t_lo + 
                pow(zeta, self.n, self.order) * proof.tau_t_mid + 
                pow(zeta, self.n*2, self.order) * proof.tau_t_hi
            )
        )

        tau_F = (
            tau_D + proof.tau_a * v + 
            proof.tau_b * pow(v, 2, self.order) +
            proof.tau_c * pow(v, 3, self.order) +
            tau_sigma1 * pow(v, 4, self.order) +
            tau_sigma2 * pow(v, 5, self.order)
        )

        tau_E = ((
            -r0 + 
            v * proof.zeta_a +
            pow(v, 2, self.order) * proof.zeta_b +
            pow(v, 3, self.order) * proof.zeta_c +
            pow(v, 4, self.order) * proof.zeta_sigma1 +
            pow(v, 5, self.order) * proof.zeta_sigma2 +
            u * proof.zeta_omega
        ) % self.order) * self.E.G1()


        lhs = self.E.pairing(proof.tau_W_zeta + u * proof.tau_W_zeta_omega, self.key.tau_g2)
        rhs = self.E.pairing(zeta * proof.tau_W_zeta + (u*zeta*omega)*proof.tau_W_zeta_omega + tau_F - tau_E, self.E.G2())

        return lhs == rhs