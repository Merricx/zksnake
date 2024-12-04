from __future__ import annotations
from multiprocessing import Value
from typing import Any, Union
from joblib import Parallel, delayed

from ..symbolic import Symbol
from ..array import SparseArray
from ..ecc import EllipticCurve
from ..utils import get_n_jobs, next_power_of_two
from .constraints import BaseConstraint

def recursive_mul(eq, qM, var_mul, touched_var, limit=2):
    l = eq.left
    r = eq.right

    if isinstance(l, Symbol) and isinstance(r, Symbol):
        if l.op == "VAR" and r.op == "VAR":
            qM *= 1
            var_mul += 2
            touched_var += [l.name, r.name]
        elif (l.op == "VAR" and r.op == "MUL") or (r.op == "VAR" and l.op == "MUL"):
            var_mul += 1
            if l.op == "MUL":
                qM = recursive_mul(l, qM, var_mul, touched_var, limit)
            if r.op == "MUL":
                qM = recursive_mul(r, qM, var_mul, touched_var, limit)
        else:
            raise ValueError("Invalid Plonkish constraint")

    elif isinstance(l, int):
        qM *= l
        if r.op == "MUL":
            qM = recursive_mul(r, qM, var_mul, touched_var, limit)
        elif r.op == "VAR":
            var_mul += 1
            touched_var += [r.name]
        else:
            raise ValueError("Invalid Plonkish constraint")

    elif isinstance(r, int):
        qM *= r
        if l.op == "MUL":
            qM = recursive_mul(l, qM, var_mul, touched_var, limit)
        elif l.op == "VAR":
            var_mul += 1
            touched_var += [l.name]
        else:
            raise ValueError("Invalid Plonkish constraint")

    else:
        raise ValueError("Invalid Plonkish constraint")
    
    if var_mul > limit:
        raise ValueError("Multiple multiplication gates detected")

    return qM


def consume_constraint(constraint, public_inputs, witness: list):
    qL = 0
    qR = 0
    qO = 0
    qM = 0
    qC = 0
    w = [None, None, None]

    left = constraint.left
    right = constraint.right

    if isinstance(left, int):
        qC -= left
    elif left.op == "VAR":
        qO = -1 if left.name not in public_inputs else 0
        w[2] = left.name
    else:
        raise ValueError(f"Constraint {constraint} not in the form of C = A*B")

    if right.op == "ADD":
        l = right.left
        r = right.right

        if isinstance(l, Symbol) and isinstance(r, Symbol):
            if l.op == "VAR" and r.op == "VAR":
                qL = 1 if l.name not in public_inputs else 0
                qR = 1 if r.name not in public_inputs else 0
                w[0] = l.name
                w[1] = r.name
            elif l.op == "MUL" or r.op == "MUL":
                qR = 1
                qL = 1
                if l.op == "MUL":
                    try:
                        touched_var = []
                        qL = recursive_mul(l, 1, 0, touched_var, 1)
                        w[0] = touched_var[0]
                    except ValueError as e:
                        raise ValueError(f"{e} at {constraint}") from e
                if r.op == "MUL":
                    try:
                        touched_var = []
                        qR = recursive_mul(r, 1, 0, touched_var, 1)
                        w[1] = touched_var[0]
                    except ValueError as e:
                        raise ValueError(f"{e} at {constraint}") from e
                    
            else:
                raise ValueError(f"Invalid Plonkish constraint at: {constraint}")
    
        elif isinstance(r, int):
            qL = 1
            w[0] = l.name
            qR = 0
            qC += r
        elif isinstance(l, int):
            qL = 0
            qR = 1
            w[1] = r.name
            qC += l
        else:
            raise ValueError(f"{right}")

        
    elif right.op == "SUB":
        l = right.left
        r = right.right

        if isinstance(l, Symbol) and isinstance(r, Symbol):
            if l.op == "VAR" and r.op == "VAR":
                qL = 1 if l.name not in public_inputs else 0
                qR = -1 if r.name not in public_inputs else 0
                w[0] = l.name
                w[1] = r.name
            else:
                if l.op == "MUL":
                    qR = -1
                    try:
                        touched_var = []
                        qL = recursive_mul(l, 1, 0, touched_var, 1)
                        w[0] = touched_var[0]
                    except ValueError as e:
                        raise ValueError(f"{e} at {constraint}") from e
                    
                if r.op == "MUL":
                    qL = 1
                    try:
                        touched_var = []
                        qR = -recursive_mul(r, 1, 0, touched_var, 1)
                        w[1] = touched_var[0]
                    except ValueError as e:
                        raise ValueError(f"{e} at {constraint}") from e
                else:
                    raise ValueError(f"Invalid Plonkish constraint at: {constraint}")
        
        elif isinstance(r, int):
            qL = 1
            w[0] = l.name
            qR = 0
            qC -= r
        elif isinstance(l, int):
            qL = 0
            qR = -1
            w[1] = r.name
            qC += l
        else:
            raise ValueError(f"{right}")
    elif right.op == "MUL":
        if isinstance(right.left, int):
            qL = right.left
            w[1] = right.right.name
        elif isinstance(right.right, int):
            qR = right.right
            w[0] = right.left.name
        else:
            qM = 1
            var_mul = 0
            try:
                touched_var = []
                qM = recursive_mul(right, qM, var_mul, touched_var)
                w[0] = touched_var[0]
                if len(touched_var) == 2:
                    w[1] = touched_var[1]
            except ValueError as e:
                raise ValueError(f"{e} at {constraint}") from e
    elif right.op == "DIV":
        raise ValueError(f"Forbidden division operation occur at {constraint}")
    elif right.op == "VAR":
        qL = 1
        w[0] = right.name
        qR = 0
    else:
        raise ValueError(f"Invalid Plonkish constraint at: {constraint}")
    
    if w[1] is not None and w[0] is None:
        w[0], w[1] = w[1], w[0]
    
    witness.extend(w)

    return qL, qR, qO, qM, qC

class ConstraintSystem(BaseConstraint):

    def __init__(
        self,
        inputs: Union[list[str], list[Symbol]],
        outputs: Union[list[str], list[Symbol]],
        curve="BN254",
    ):
        super().__init__(inputs, outputs)
        self.p = EllipticCurve(curve).order
        self.witness_map = None

    def _split_accumulator(self):
        pass

    def _copy_constraint(self, witness_map):
        size = len(witness_map)
        padded_size = next_power_of_two(len(self.constraints))*3
        padded_witness = witness_map + [None]*(padded_size - size)
        w = [x for i in range(3) for x in padded_witness[i::3]]
        permutation = [i for i in range(padded_size)]
        
        for i in range(size):
            if w[i] is None:
                continue
            for j in range(i+1, size):
                if w[i] == w[j]:
                    permutation[i], permutation[j] = permutation[j], permutation[i]
                    break

        return permutation

    def evaluate(self, input_values: dict, output_values: dict = None) -> bool:
        """Evaluate the constraint system with given inputs and output"""
        output_values = output_values or {}
        if len(input_values) != len(self.inputs):
            raise ValueError(
                "Length of input values differ with input variables")

        for k, _ in self.vars.items():
            self.vars[k] = None

        for inp in self.inputs:
            if inp not in self.vars:
                self.temp_vars.append(inp)

            self.vars[inp] = input_values.get(inp, 0) % self.p

        constraints_stack = self.constraints[:]

        while True:
            self._consume_hint()
            remaining = self._consume_constraint_stack(constraints_stack)
            constraints_stack = remaining

            if not remaining:
                break

        for out in output_values:
            output_value = output_values[out]
            assert (
                output_value % self.p == self.vars[out]
            ), f"{output_value} != {self.vars[out]}"

        return True
    
    def solve(self, input_values, output_value = None):
        """
        Generate witness by solving the constraint system with given inputs
        (optionally, with given outputs)

        Args:
            input_values: dict mapping of input variables and values
            output_value: output value of the equation

        Returns:
            witness: tuple of (public_witness, private_witness)
        """
        if not self.witness_map:
            raise ValueError("Plonkish constraints must be compiled first before the witness can be generated")

        if not self.evaluate(input_values, output_value):
            raise ValueError(
                "Evaluated constraints are not satisfied with given input")

        pub_w = {}
        priv_w = {}
        for k,v in self.vars.items():
            if k in self.public:
                pub_w[k] = v
            else:
                priv_w[k] = v
    
        private_witness = []
        pi = []
        for i in range(0, len(self.witness_map), 3):
            k1 = self.witness_map[i]
            k2 = self.witness_map[i+1]
            k3 = self.witness_map[i+2]

            private_witness += [priv_w[k1]] if k1 is not None else [0]
            private_witness += [priv_w[k2]] if k2 is not None else [0]
            if k3 in pub_w:
                pi += [-pub_w[k3] % self.p]
                private_witness += [0]
            else:
                pi += [0]
                private_witness += [priv_w[k3]] if k3 is not None else [0]

        return pi, private_witness
    
    def compile(self):
        """
        Compile list of constraints into Plonkish object

        Returns:
            circuit: Plonkish object
        """
        witness = []
        
        qL = []
        qR = []
        qO = []
        qM = []
        qC = []

        for c in self.constraints:
            result = consume_constraint(c, self.public, witness)
            qL.append(result[0] % self.p)
            qR.append(result[1] % self.p)
            qO.append(result[2] % self.p)
            qM.append(result[3] % self.p)
            qC.append(result[4] % self.p)

        permutation = self._copy_constraint(witness)
        # print(f"{witness=}")
        # print(f"{permutation=}")
        # print(f"{qL=}")
        # print(f"{qR=}")
        # print(f"{qO=}")
        # print(f"{qM=}")
        # print(f"{qC=}")

        self.witness_map = witness

        return Plonkish(qL, qR, qO, qM, qC, witness, permutation, self.p)

class Plonkish:

    def __init__(self, 
        qL: list,
        qR: list,
        qO: list,
        qM: list,
        qC: list,
        witness_map: list,
        permutation: list,
        p: int
    ):
        self.unpadded_length = len(qL)
        self.length = next_power_of_two(len(qL))
        self.qL = qL + [0]*(self.length - len(qL))
        self.qR = qR + [0]*(self.length - len(qR))
        self.qO = qO + [0]*(self.length - len(qO))
        self.qM = qM + [0]*(self.length - len(qM))
        self.qC = qC + [0]*(self.length - len(qC))
        self.witness_map = witness_map
        self.permutation = permutation
        self.p = p

    def is_sat(self, public_witness: list, private_witness: list):

        pi = public_witness
        a,b,c = private_witness[::3], private_witness[1::3], private_witness[2::3]
        
        # print(f"{a=}")
        # print(f"{b=}")
        # print(f"{c=}")
        # print(f"{pi=}")

        for i in range(self.unpadded_length):
            g = (
                self.qL[i] * a[i] +
                self.qR[i] * b[i] +
                self.qM[i] * (a[i] * b[i]) +
                self.qO[i] * c[i] +
                (self.qC[i] + pi[i])
            )

            if g % self.p != 0:
                return False
            
        return True

    def to_bytes(self):
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, data):
        raise NotImplementedError
