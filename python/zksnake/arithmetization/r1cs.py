from __future__ import annotations

# pylint: disable=no-name-in-module
from zksnake._algebra import circuit

from ..parser import R1CSReader
from ..array import SparseArray
from ..ecc import EllipticCurve


class R1CS:

    def __init__(self, cs: circuit.ConstraintSystem, curve: str = "BN254"):
        self.A = None
        self.B = None
        self.C = None
        self.constraint_system = cs
        self.n_public = len(cs.public_vars) + 1
        self.p = EllipticCurve(curve).order

    def compile(self):
        """
        Compile Constraint System into R1CS Sparse Array
        """
        compiled = self.constraint_system.compile_to_r1cs()

        row_length = self.constraint_system.num_constraints()
        col_length = self.constraint_system.num_witness() + 1

        A = SparseArray([[]], row_length, col_length, self.p)
        B = SparseArray([[]], row_length, col_length, self.p)
        C = SparseArray([[]], row_length, col_length, self.p)

        for row in compiled:
            A.append(row[0])
            B.append(row[1])
            C.append(row[2])

        self.A = A
        self.B = B
        self.C = C

    def generate_witness(self, solve_result: dict):
        """
        Generate R1CS full witness from solved Constraint System
        """
        w = []

        for v in self.constraint_system.get_witness_vector():
            if v == "0":
                w.append(1)
            elif isinstance(v, str):
                w.append(solve_result[v] % self.p)
            else:
                w.append(v % self.p)

        return w[: self.n_public], w[self.n_public :]

    def is_sat(self, public_witness: list, private_witness: list):
        """
        Check R1CS satisfiability with the given `witness`
        """
        assert self.A is not None, "R1CS is not compiled"

        w = public_witness + private_witness
        Az = self.A.dot(w)
        Bz = self.B.dot(w)
        Cz = self.C.dot(w)

        AzBz = [x * y % self.p for x, y in zip(Az, Bz)]

        return AzBz == Cz

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

    @classmethod
    def from_file(cls, r1csfile: str, symfile: str = None, curve: str = "BN254"):

        p = EllipticCurve(curve).order

        reader = R1CSReader(r1csfile, symfile)
        result = reader.read()

        output_offset = result["header"]["n_pub_out"] + 1
        public_offset = output_offset + result["header"]["n_pub_in"]
        private_offset = public_offset + result["header"]["n_priv_in"]
        outputs = result["wires"][1:output_offset]
        public_inputs = result["wires"][output_offset:public_offset]
        private_inputs = result["wires"][public_offset:private_offset]

        inputs_str = [str(x) for x in public_inputs + private_inputs]
        outputs_str = [str(x) for x in outputs]

        cs = circuit.ConstraintSystem(inputs_str, outputs_str, p)
        for wire in result["wires"][1:]:
            cs.add_variable(wire)

        cs.set_public(outputs)
        cs.set_public(public_inputs)

        for constraint in result["constraints"]:
            cs.add_constraint(constraint)

        return R1CS(cs, curve)
