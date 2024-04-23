from .symbolic import Symbol, Equation, symeval
from .ecc import EllipticCurve
from .qap import QAP


class ConstraintSystem:

    def __init__(
        self, inputs: list[str] | list[Symbol], output: str | Symbol, curve="BN128"
    ):
        self.vars = {}
        self.constraints = []
        self.public = []
        self.p = EllipticCurve(curve).curve.curve_order

        if inputs and isinstance(inputs[0], Symbol):
            self.inputs = [x.name for x in inputs]
        else:
            self.inputs = inputs

        if isinstance(output, Symbol):
            self.output = output.name
        else:
            self.output = output

    def __add_var(self, eq):
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
            v for v in self.vars if v not in self.inputs and v != self.output
        ]

        return [1] + public_input + [self.output] + private_input + intermediate_vars

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
            eq: Equation to be added to the constraint system
        """
        self.constraints.append(eq)
        self.__add_var(eq)

    def set_public(self, public_vars: str | Symbol | list[str] | list[Symbol]):
        """
        Set variable(s) in the constraint system to be public.

        Args:
            public_vars: One or more variables in `str` or `Symbol` which will be made public
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

    def evaluate(self, input_values: dict, output_value: int) -> bool:
        """Evaluate the constraint system with given inputs and output"""

        if len(input_values) != len(self.inputs):
            raise ValueError("Length of input values differ with input variables")

        for inp in self.inputs:
            self.vars[inp] = input_values.get(inp, 0) % self.p

        self.vars[self.output] = output_value % self.p

        satisfied_constraints = []
        for constraint in self.constraints:

            left = constraint.left
            right = constraint.right

            if isinstance(left, Symbol) and left.op == "VAR":
                self.vars[left.name] = symeval(right, self.vars, self.p)
            elif isinstance(left, int):
                evaluated_right = symeval(right, self.vars, self.p)
                satisfied_constraints.append(left % self.p == evaluated_right)
            else:
                evaluated_left = symeval(left, self.vars, self.p)
                evaluated_right = symeval(right, self.vars, self.p)

                satisfied_constraints.append(evaluated_left == evaluated_right)

        satisfied_constraints.append(output_value % self.p == self.vars[self.output])

        return all(satisfied_constraints)

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
            input_values: Mapping of input variables and values
            output_value: Output value of the equation

        Returns:
            witness: Tuple of (public_witness, private_witness)
        """
        self.__add_dummy_constraints()
        witness = self.__get_witness_vector()
        if not self.evaluate(input_values, output_value):
            raise ValueError("Evaluated constraints are not satisfied with given input")

        w = self.__evaluate_witness_vector(witness)

        return w[: len(self.public) + 1], w[len(self.public) + 1 :]

    def from_file(self, filepath):
        pass

    def to_file(self, filepath):
        pass
