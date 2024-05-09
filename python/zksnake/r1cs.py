from typing import Union
from .symbolic import Symbol, Equation, symeval, get_unassigned_var
from .ecc import EllipticCurve
from .qap import QAP
from .parser import R1CSReader


class ConstraintSystem:

    def __init__(
        self,
        inputs: Union[list[str], list[Symbol]],
        outputs: Union[list[str], list[Symbol]],
        curve="BN128",
    ):
        self.vars = {}
        self.constraints = []
        self.public = []
        self.p = EllipticCurve(curve).order

        if inputs and isinstance(inputs[0], Symbol):
            self.inputs = [x.name for x in inputs]
        else:
            self.inputs = inputs

        if outputs and isinstance(outputs[0], Symbol):
            self.outputs = [x.name for x in outputs]
        else:
            self.outputs = outputs

        # outputs always public
        self.set_public(outputs)

    def __add_var(self, eq: Symbol):
        if isinstance(eq, int):
            return

        if eq.op == "VAR":
            if eq.name not in self.vars:
                self.vars[eq.name] = None
        else:
            self.__add_var(eq.left)
            self.__add_var(eq.right)

    def __transform(self, eq, witness, vec, is_neg=False):

        if isinstance(eq, int):
            vec[0] = (-eq if is_neg else eq) % self.p
            return

        if eq.op == "VAR":
            index = witness.index(eq.name)
            if eq.is_negative or is_neg:
                vec[index] = (-1) % self.p
            else:
                vec[index] = 1
        elif eq.op == "ADD":
            l = eq.left
            r = eq.right

            self.__transform(l, witness, vec)
            self.__transform(r, witness, vec)
        elif eq.op == "SUB":
            l = eq.left
            r = eq.right

            self.__transform(l, witness, vec)
            self.__transform(r, witness, vec, True)
        elif eq.op == "MUL":
            l = eq.left
            r = eq.right

            if isinstance(l, Symbol) and isinstance(r, Symbol):
                raise ValueError(f"Multiple multiplication occur at {eq}")

            if isinstance(r, int):
                l, r = r, l

            index = witness.index(r.name)
            vec[index] = (-l if is_neg else l) % self.p

        elif eq.op == "DIV":
            raise ValueError(f"Forbidden division operation occur at {eq}")
        else:
            raise ValueError(f"Invalid operation at {eq}")

    def __get_witness_vector(self):
        public_input = [v for v in self.vars if v in self.inputs and v in self.public]
        private_input = [
            v for v in self.vars if v in self.inputs and v not in self.public
        ]
        intermediate_vars = [
            v for v in self.vars if v not in self.inputs and v not in self.outputs
        ]

        return [1] + self.outputs + public_input + private_input + intermediate_vars

    def __evaluate_witness_vector(self, witness):
        w = []
        for v in witness:
            if isinstance(v, str):
                w.append(self.vars[v] % self.p)
            else:
                w.append(v % self.p)

        return w

    def add(self, eq: Equation):
        """
        Add new constraint to the system.

        Args:
            eq: equation to be added to the constraint system
        """
        self.constraints.append(eq)
        self.__add_var(eq)

    def set_public(self, public_vars: Union[str, Symbol, list[str], list[Symbol]]):
        """
        Set variable(s) in the constraint system to be public.

        Args:
            public_vars: one or more variables in `str` or `Symbol` which will be made public
        """
        if isinstance(public_vars, list):
            for var in public_vars:
                if isinstance(var, str):
                    self.public += [var]
                elif isinstance(var, Symbol):
                    self.public += [var.name]
                else:
                    raise TypeError(f"Invalid type of {var}")
        elif isinstance(public_vars, str):
            self.public += [public_vars]
        elif isinstance(public_vars, Symbol):
            self.public += [public_vars.name]
        else:
            raise TypeError(f"Invalid type of {public_vars}")

    def __consume_constraint_stack(self, constraints_stack: list):
        skipped_constraints = []
        for constraint in constraints_stack:

            left = constraint.left
            right = constraint.right

            try:
                original_left = left
                coeff = 1
                if isinstance(left, Symbol) and left.op != "VAR":
                    target, coeff = get_unassigned_var(left, self.vars)

                    if target:
                        left = target

                if isinstance(left, Symbol) and left.op == "VAR":
                    evaluated_right = symeval(right, self.vars, self.p)
                    if self.vars[left.name] is None:
                        # assign the value to variable in the lhs
                        # by moving known values in lhs to rhs
                        # and add/subtract to the evaluation of rhs

                        self.vars[left.name] = 0
                        diff = symeval(original_left, self.vars, self.p)

                        inv_coeff = pow(coeff, -1, self.p)
                        val_1 = (evaluated_right - diff) * inv_coeff % self.p
                        val_2 = (evaluated_right + diff) * inv_coeff % self.p

                        self.vars[left.name] = val_1
                        check = symeval(original_left, self.vars, self.p)
                        if check != evaluated_right:
                            self.vars[left.name] = val_2

                            check = symeval(original_left, self.vars, self.p)
                            assert (
                                check == evaluated_right
                            ), f"{check} != {evaluated_right}"

                    else:
                        # variable in the lhs already assigned, check the equality instead
                        evaluated_left = self.vars[left.name]

                        assert (
                            evaluated_left == evaluated_right
                        ), f"{evaluated_left} != {evaluated_right}"
                elif isinstance(left, int):
                    # no variable assignment, with lhs being constant integer
                    evaluated_right = symeval(right, self.vars, self.p)

                    assert (
                        evaluated_left == evaluated_right
                    ), f"{evaluated_left} != {evaluated_right}"
                else:
                    # no variable assignment, directly check if lhs == rhs hold
                    evaluated_left = symeval(left, self.vars, self.p)
                    evaluated_right = symeval(right, self.vars, self.p)

                    assert (
                        evaluated_left == evaluated_right
                    ), f"{evaluated_left} != {evaluated_right}"
            except ValueError:
                skipped_constraints.append(constraint)

        if skipped_constraints and len(skipped_constraints) == len(constraints_stack):
            raise ValueError(
                f"There is more than one unknown value at : {skipped_constraints[0]}"
            )

        return skipped_constraints

    def evaluate(self, input_values: dict, output_values: dict) -> bool:
        """Evaluate the constraint system with given inputs and output"""

        if len(input_values) != len(self.inputs):
            raise ValueError("Length of input values differ with input variables")

        for inp in self.inputs:
            self.vars[inp] = input_values.get(inp, 0) % self.p

        # for out in self.outputs:
        #     self.vars[out] = output_values.get(out, 0) % self.p

        constraints_stack = self.constraints[:]

        while True:
            remaining = self.__consume_constraint_stack(constraints_stack)
            constraints_stack = remaining

            if not remaining:
                break

        for out in output_values:
            output_value = output_values[out]
            assert (
                output_value % self.p == self.vars[out]
            ), f"{output_value} != {self.vars[out]}"

        return True

    def __add_dummy_constraints(self):
        """
        Add dummy constraints to prevent proof malleability from unused public input
        See: https://geometry.xyz/notebook/groth16-malleability
        """
        for public in self.public:
            if public not in self.vars:
                var = Symbol(public)
                eq = 0 == var * 0
                self.constraints.append(eq)
                self.__add_var(eq)

    def compile(self) -> QAP:
        """
        Compile R1CS into Quadratic Arithmetic Program (QAP)

        Returns:
            qap: QAP object of the constraint system
        """
        self.__add_dummy_constraints()
        witness = self.__get_witness_vector()

        row_length = len(witness)
        A, B, C = [], [], []

        for constraint in self.constraints:

            a = [0] * row_length
            b = [0] * row_length
            c = [0] * row_length

            left = constraint.left
            right = constraint.right

            if right.op == "ADD":
                self.__transform(right, witness, a)
                b[0] = 1

                self.__transform(left, witness, c)
            elif right.op == "SUB":
                self.__transform(right, witness, a, True)
                b[0] = 1

                self.__transform(left, witness, c)
            elif right.op == "MUL":
                self.__transform(right.left, witness, a)
                self.__transform(right.right, witness, b)

                self.__transform(left, witness, c)
            elif right.op == "DIV":
                self.__transform(right.left, witness, c)
                self.__transform(right.right, witness, b)

                self.__transform(left, witness, a)
            elif right.op == "VAR":
                self.__transform(right, witness, a)
                b[0] = 1

                self.__transform(left, witness, c)
            else:
                raise ValueError(f"Invalid constraint at: {constraint}")

            A.append(a)
            B.append(b)
            C.append(c)

        qap = QAP(self.p)
        qap.from_r1cs(A, B, C, len(self.public) + 1)

        return qap

    def solve(self, input_values: dict, output_value: int) -> list:
        """
        Evaluate the constraint system with given inputs and output

        Args:
            input_values: dict mapping of input variables and values
            output_value: output value of the equation

        Returns:
            witness: tuple of (public_witness, private_witness)
        """
        self.__add_dummy_constraints()
        witness = self.__get_witness_vector()
        print(witness)
        if not self.evaluate(input_values, output_value):
            raise ValueError("Evaluated constraints are not satisfied with given input")

        w = self.__evaluate_witness_vector(witness)

        return w[: len(self.public) + 1], w[len(self.public) + 1 :]

    @classmethod
    def from_file(cls, r1csfile: str, symfile: str = None):

        reader = R1CSReader(r1csfile, symfile)
        result = reader.read()

        output_offset = result["header"]["n_pub_out"] + 1
        public_offset = output_offset + result["header"]["n_pub_in"]
        private_offset = public_offset + result["header"]["n_priv_in"]
        outputs = result["wires"][1:output_offset]
        public_inputs = result["wires"][output_offset:public_offset]
        private_inputs = result["wires"][public_offset:private_offset]

        cs = ConstraintSystem(public_inputs + private_inputs, outputs)
        cs.set_public(public_inputs)

        for constraint in result["constraints"]:
            # print(constraint)
            cs.add(constraint)

        return cs

    def to_file(self, filepath):
        raise NotImplementedError
