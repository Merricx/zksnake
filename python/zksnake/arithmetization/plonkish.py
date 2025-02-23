from __future__ import annotations

# pylint: disable=no-name-in-module
from zksnake._algebra import circuit

from ..ecc import EllipticCurve
from ..utils import next_power_of_two


class Plonkish:

    def __init__(self, cs: circuit.ConstraintSystem, curve: str = "BN254"):
        size = cs.num_constraints()
        self.constraint_system = cs
        self.unpadded_length = size
        self.length = next_power_of_two(size)
        self.qL = None
        self.qR = None
        self.qO = None
        self.qM = None
        self.qC = None
        self.witness_map = []
        self.permutation = []
        self.p = EllipticCurve(curve).order

    def compile(self):
        """
        Compile Constraint System into Plonk Polynomials (coefficient form)
        """
        compiled = self.constraint_system.compile_to_plonkish()

        qL = []
        qR = []
        qM = []
        qO = []
        qC = []
        witness_map = []
        for c in compiled[0]:
            qL += [c[0]]
            qR += [c[1]]
            qO += [c[2]]
            qM += [c[3]]
            qC += [c[4]]
            witness_map.extend(c[5])

        self.qL = qL + [0] * (self.length - len(qL))
        self.qR = qR + [0] * (self.length - len(qR))
        self.qO = qO + [0] * (self.length - len(qO))
        self.qM = qM + [0] * (self.length - len(qM))
        self.qC = qC + [0] * (self.length - len(qC))
        self.witness_map = witness_map

        self.permutation = compiled[1]

    def solve(self, inputs: dict) -> dict:
        """
        Solve the constraint system with given inputs,
        return the solution dict
        """
        return self.constraint_system.solve(inputs)

    def generate_witness(self, solve_result: dict):
        """
        Generate Plonk full witness from solved Constraint System
        """
        pub_w = {}
        priv_w = {}
        for k, v in solve_result.items():
            if k in self.constraint_system.public_vars:
                pub_w[k] = v

            priv_w[k] = v

        private_witness = []
        pi = {}
        pi_index = 0
        for i in range(0, len(self.witness_map), 3):
            k1 = self.witness_map[i]
            k2 = self.witness_map[i + 1]
            k3 = self.witness_map[i + 2]

            private_witness += [priv_w[k1]] if k1 else [0]
            private_witness += [priv_w[k2]] if k2 else [0]
            if k3 in pub_w:
                pi[pi_index] = -pub_w[k3] % self.p
                pi_index += 1
                private_witness += [0]
            else:
                pi_index += 1
                private_witness += [priv_w[k3]] if k3 else [0]

        return pi, private_witness

    def is_sat(self, public_witness: dict, private_witness: list):
        """
        Check constraint satisfiability with the given `witness`
        """
        a, b, c = private_witness[::3], private_witness[1::3], private_witness[2::3]

        # gate constraints
        for i in range(self.unpadded_length):
            pi = public_witness.get(i, None) or 0
            g = (
                self.qL[i] * a[i]
                + self.qR[i] * b[i]
                + self.qM[i] * (a[i] * b[i])
                + self.qO[i] * c[i]
                + (self.qC[i] + pi)
            )

            if g % self.p != 0:
                return False

        # copy constraints
        a += [0] * (self.length - len(a))
        b += [0] * (self.length - len(b))
        c += [0] * (self.length - len(c))
        flatten_witness = a + b + c
        for src, dst in enumerate(self.permutation):
            if flatten_witness[src] != flatten_witness[dst]:
                return False

        return True

    def to_bytes(self):
        """
        Serialize R1CS object into bytes
        """
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, data):
        """
        Construct R1CS object from bytes
        """
        raise NotImplementedError
