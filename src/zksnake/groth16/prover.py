import random
from ..ecc import EllipticCurve
from ..qap import QAP

class Proof:

    def __init__(self, A=None, B=None, C=None):
        self.A = A
        self.B = B
        self.C = C

    def __str__(self):
        return f"A = {self.A}\nB = {self.B}\nC = {self.C}"
    
    def __repr__(self):
        return self.__str__()
    
    def from_hex(self, s: str):
        pass

    def to_hex(self) -> str:
        pass

class ProvingKey:
    def __init__(
            self,
            alpha_G1,
            beta_G1,
            beta_G2,
            delta_G1,
            delta_G2,
            tau_G1,
            tau_G2,
            target_G1,
            k_delta_G1
        ):
        self.alpha1 = alpha_G1
        self.beta1 = beta_G1
        self.beta2 = beta_G2
        self.delta1 = delta_G1
        self.delta2 = delta_G2
        self.tau1 = tau_G1
        self.tau2 = tau_G2
        self.target1 = target_G1
        self.kdelta1 = k_delta_G1

    def from_hex(self, s: str):
        pass

    def to_hex(self) -> str:
        pass

class Prover:
    def __init__(self, qap: QAP, key: ProvingKey, curve: str='BN128'):
        """
        Prover object

        Args:
            qap: QAP to be proved from
            key: `ProvingKey` from trusted setup
            curve: `BN128` or `BLS12_381`
        """
        self.qap = qap
        self.key = key
        self.E = EllipticCurve(curve)
        self.order = self.E.curve.curve_order

    def __urandom(self):
        rand = random.SystemRandom()
        return rand.randint(1, self.order - 1)

    def prove(self, private_witness: list, public_witness: list) -> Proof:
        """
        Prove statement from QAP by providing public+private witness
        """
        
        r = self.__urandom()
        s = self.__urandom()

        try:
            U, V, W, H = self.qap.evaluate_witness(public_witness + private_witness)
        except ValueError:
            raise ValueError(f"Failed to evaluate with the given witness")

        A = V(self.key.tau1) + self.key.alpha1 + (self.key.delta1 * r)
        B1 = U(self.key.tau1) + self.key.beta1 + (self.key.delta1 * s)
        B2 = U(self.key.tau2) + self.key.beta2 + (self.key.delta2 * s)
        HT = H(self.key.target1)

        delta_witness = [point * scalar for point, scalar in zip(self.key.kdelta1, private_witness)]
        sum_delta_witness = delta_witness[0]
        for k in delta_witness[1:]:
            sum_delta_witness += k

        C = HT + sum_delta_witness + (A * s) + (B1 * r) + (-self.key.delta1 * (r*s%self.order))

        return Proof(A, B2, C)