from __future__ import annotations
from typing import Any, Union, Callable
from joblib import Parallel, delayed

from .symbolic import Symbol, SymbolArray, Equation, symeval, get_unassigned_var
from .array import SparseArray
from .ecc import EllipticCurve
from .qap import QAP
from .parser import R1CSReader
from .utils import get_n_jobs


def __transform(row, eq, witness, vec: list, p, is_neg=False):
    if isinstance(eq, int):
        value = (-eq if is_neg else eq) % p
        vec.append((row, 0, value))
        return

    if eq.op == "VAR":
        index = witness.index(eq.name)
        if eq.is_negative or is_neg:
            vec.append((row, index, (-1) % p))
        else:
            vec.append((row, index, 1))
    elif eq.op == "ADD":
        l = eq.left
        r = eq.right

        __transform(row, l, witness, vec, p)
        __transform(row, r, witness, vec, p)
    elif eq.op == "SUB":
        l = eq.left
        r = eq.right

        __transform(row, l, witness, vec, p)
        __transform(row, r, witness, vec, p, True)
    elif eq.op == "MUL":
        l = eq.left
        r = eq.right

        if isinstance(l, Symbol) and isinstance(r, Symbol):
            raise ValueError(f"Constraint {eq} not in the form of C = A*B")

        if isinstance(r, int):
            l, r = r, l

        index = witness.index(r.name)
        value = (-l if is_neg else l) % p
        vec.append((row, index, value))

    elif eq.op == "DIV":
        raise ValueError(f"Forbidden division operation occur at {eq}")
    else:
        raise ValueError(f"Invalid operation at {eq}")


def consume_constraint(row, constraint, witness, p):
    a = []
    b = []
    c = []

    left = constraint.left
    right = constraint.right

    if right.op == "ADD":
        __transform(row, right, witness, a, p)
        b.append((row, 0, 1))

        __transform(row, left, witness, c, p)
    elif right.op == "SUB":
        __transform(row, right, witness, a, p, True)
        b.append((row, 0, 1))

        __transform(row, left, witness, c, p)
    elif right.op == "MUL":
        __transform(row, right.left, witness, a, p)
        __transform(row, right.right, witness, b, p)

        __transform(row, left, witness, c, p)
    elif right.op == "DIV":
        __transform(row, right.left, witness, c, p)
        __transform(row, right.right, witness, b, p)

        __transform(row, left, witness, a, p)
    elif right.op == "VAR":
        __transform(row, right, witness, a, p)
        b.append((row, 0, 1))

        __transform(row, left, witness, c, p)
    else:
        raise ValueError(f"Invalid constraint at: {constraint}")

    return a, b, c


class BaseConstraint:
    def __init__(
        self,
        inputs: Union[list[str], list[Union[Symbol, SymbolArray]]],
        outputs: Union[list[str], list[Union[Symbol, SymbolArray]]],
    ):
        self.vars = {}
        self.temp_vars = []
        self.hints = {}
        self.constraints = []
        self.public = []
        self.p = None

        self.inputs = []
        self.outputs = []
        if isinstance(inputs, list):
            for var in inputs:
                if isinstance(var, str):
                    self.inputs += [var]
                elif isinstance(var, Symbol):
                    self.inputs += [var.name]
                elif isinstance(var, SymbolArray):
                    self.inputs += var.explode()
                else:
                    raise TypeError(f"Invalid type of {var}")

        if isinstance(outputs, list):
            for var in outputs:
                if isinstance(var, str):
                    self.outputs += [var]
                elif isinstance(var, Symbol):
                    self.outputs += [var.name]
                elif isinstance(var, SymbolArray):
                    self.outputs += var.explode()
                else:
                    raise TypeError(f"Invalid type of {var}")

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

    def add_constraint(self, eq: Equation):
        """
        Add new constraint to the system.

        Args:
            eq: equation to be added to the constraint system
        """
        self.constraints.append(eq)
        self.__add_var(eq)

    def add_template(
        self,
        template: ConstraintTemplate,
    ):
        """
        Add constraints from ConstraintTemplate

        Args:
            template: ConstraintTemplate object
        """

        # inject constraints from template
        for constraint in template.constraints:
            self.add_constraint(constraint)

        # inject hints from template
        for target, (func, args) in template.hints.items():
            self.add_hint(func, target, args)

    def add_hint(
        self, func: Callable[[Any], int], target: Union[Symbol, str], args: Any = None
    ):
        """
        Add hint function to pre-define variable value outside constraints evaluation
        """
        args = args or []
        target = target if isinstance(target, str) else target.name
        self.hints[target] = (func, args)

    def set_public(
        self,
        public_vars: Union[
            str, Symbol, SymbolArray, list[str], list[Symbol], list[SymbolArray]
        ],
    ):
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
                elif isinstance(var, SymbolArray):
                    self.public += var.explode()
                else:
                    raise TypeError(f"Invalid type of {var}")
        elif isinstance(public_vars, str):
            self.public += [public_vars]
        elif isinstance(public_vars, Symbol):
            self.public += [public_vars.name]
        elif isinstance(public_vars, SymbolArray):
            self.public += public_vars.explode()
        else:
            raise TypeError(f"Invalid type of {public_vars}")


class ConstraintTemplate(BaseConstraint):

    def __init__(self):
        super().__init__([], [])
        self.input_args = []
        self.output_args = []
        self.input_names = []
        self.output_names = []
        self.is_instance = False
        self.name = self.__class__.__name__

    def __add_class_prefix(self, name: str):
        prefix = self.name

        if (
            not name.startswith(prefix + ".")
            and name not in self.input_names
            and name not in self.output_names
        ):
            return f"{prefix}.{name}"
        return name

    def __intercept_var(self, eq: Union[Symbol, int, str]):
        if isinstance(eq, str):
            eq = Symbol(eq)

        if not isinstance(eq, Symbol):
            return

        if eq.op == "VAR":
            eq.name = self.__add_class_prefix(eq.name)
        else:
            self.__intercept_var(eq.left)
            self.__intercept_var(eq.right)

    def add_constraint(self, eq: Equation):
        self.__intercept_var(eq)
        return super().add_constraint(eq)

    def add_hint(
        self, func: Callable[[Any], int], target: Union[Symbol, str], args: Any = None
    ):

        target = target.name if isinstance(target, Symbol) else target
        target = Symbol(self.__add_class_prefix(target))

        args = args or []

        args = [
            (
                Symbol(self.__add_class_prefix(arg.name))
                if isinstance(arg, Symbol)
                else arg
            )
            for arg in args
        ]

        return super().add_hint(func, target, args)

    def main(self, *args):
        raise NotImplementedError(
            f"main function of {self.__class__.__name__} is not implemented"
        )

    def __call__(self, namespace: str, *inputs):
        self.constraints = []
        self.input_args = list(inputs)
        self.name = namespace

        if "." in namespace:
            raise ValueError("Namespace cannot contains dot (.) character")

        return self

    def __map_input_output(self, val):
        for v in val:
            if isinstance(v, SymbolArray):
                self.input_names.extend(v.explode())
            elif isinstance(v, Symbol):
                self.input_names.append(v.name)
            elif isinstance(v, list):
                self.__map_input_output(v)

    def __eq__(self, value: Union[Symbol, SymbolArray]):

        self.constraints = []
        self.is_instance = True
        self.output_args = [value]

        self.__map_input_output(self.input_args)

        if isinstance(value, SymbolArray):
            self.output_names = value.explode()
        elif isinstance(value, Symbol):
            self.output_names = [value.name]

        self.main(*self.input_args, value)

        return self


class ConstraintSystem(BaseConstraint):

    def __init__(
        self,
        inputs: Union[list[str], list[Symbol]],
        outputs: Union[list[str], list[Symbol]],
        curve="BN254",
    ):
        super().__init__(inputs, outputs)
        self.p = EllipticCurve(curve).order

    # pylint false positive
    # pylint: disable=unused-private-member
    def __add_var(self, eq: Symbol):
        self._BaseConstraint__add_var(eq)  # pylint: disable=no-member

    def __get_witness_vector(self):
        public_input = [v for v in self.vars if v in self.inputs and v in self.public]
        private_input = [
            v
            for v in self.vars
            if v in self.inputs and v not in self.public and v not in self.temp_vars
        ]
        intermediate_vars = [
            v
            for v in self.vars
            if v not in self.inputs
            and v not in self.outputs
            and v not in self.temp_vars
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

    def __consume_constraint_stack(self, constraints_stack: list):
        skipped_constraints = []
        for constraint in constraints_stack:
            # print(self.vars)
            # print(constraint)
            # print()
            left = constraint.left
            right = constraint.right

            if isinstance(left, Symbol) and isinstance(right, Symbol):
                # if lhs is single assigned var, swap lhs and rhs
                if left.op == "VAR" and self.vars[left.name] is not None:
                    left, right = right, left

                # if lhs is multiple vars but all assigned and rhs is not, swap lhs and rhs
                elif (
                    not get_unassigned_var(left, self.vars)[0]
                    and get_unassigned_var(right, self.vars)[0]
                ):
                    left, right = right, left

            try:
                original_left = left
                coeff = 1
                multiplier = 1
                if (
                    isinstance(left, Symbol)
                    and left.op not in ["VAR", "MUL"]
                    and right.op in ["MUL", "DIV", "VAR"]
                ):
                    # Assign c in the form of c + v1 + v2 ... = (a)*(b)
                    target, coeff = get_unassigned_var(left, self.vars)

                    if target:
                        left = target

                elif isinstance(left, Symbol) and left.op == "MUL":
                    # Assign a/b in the form of (a)*(b) = c + v1 + v2 ...
                    target, coeff = get_unassigned_var(left, self.vars)

                    if target:
                        l = left.left
                        r = left.right

                        target_l, coeff_l = get_unassigned_var(l, self.vars)
                        target_r, coeff_r = get_unassigned_var(r, self.vars)

                        if target_l and not target_r:
                            target = target_l
                            coeff = coeff_l
                            left = target
                            multiplier = pow(symeval(r, self.vars, self.p), -1, self.p)

                        elif not target_l and target_r:
                            target = target_r
                            coeff = coeff_r
                            left = target
                            multiplier = pow(symeval(l, self.vars, self.p), -1, self.p)

                        else:
                            raise ValueError()

                if isinstance(left, Symbol) and left.op == "VAR":
                    evaluated_right = symeval(right, self.vars, self.p)
                    if self.vars[left.name] is None:
                        # assign the value to variable in the lhs
                        # by moving known values in lhs to rhs
                        # and add/subtract to the evaluation of rhs

                        self.vars[left.name] = 0
                        diff = symeval(original_left, self.vars, self.p)

                        inv_coeff = pow(coeff, -1, self.p)

                        # there will be 4 possible values in total:
                        # [val_1, -val_1, val_2, -val2]
                        val_1 = (
                            (evaluated_right - diff) * inv_coeff * multiplier % self.p
                        )
                        val_2 = (
                            (evaluated_right + diff) * inv_coeff * multiplier % self.p
                        )

                        for v in (val_1, -val_1, val_2, -val_2):
                            self.vars[left.name] = v % self.p
                            check = symeval(original_left, self.vars, self.p)

                            if check == evaluated_right:
                                break

                        assert check == evaluated_right, f"{check} != {evaluated_right}"

                    else:
                        # variable in the lhs already assigned, check the equality instead
                        evaluated_left = self.vars[left.name]

                        assert (
                            evaluated_left == evaluated_right
                        ), f"{evaluated_left} != {evaluated_right}"
                elif isinstance(left, int):
                    # lhs is constant integer, check if there is unassigned var in rhs

                    l = right.left
                    r = right.right

                    # check both unassigned in l * r in case both of them is same var
                    target_l, coeff_l = get_unassigned_var(l, self.vars)
                    target_r, coeff_r = get_unassigned_var(r, self.vars)

                    if (target_l and not target_r) or (not target_l and target_r):
                        target = target_l or target_r
                        coeff = coeff_l or coeff_r

                        self.vars[target.name] = 0

                        eval_l = (
                            l if isinstance(l, int) else symeval(l, self.vars, self.p)
                        )
                        eval_r = (
                            r if isinstance(r, int) else symeval(r, self.vars, self.p)
                        )

                        if not target_l:
                            eval_known = eval_l
                            eval_unknown = eval_r
                        else:
                            eval_known = eval_r
                            eval_unknown = eval_l

                        # 0 == (x+l) * (y+r)
                        # l == -x
                        if left == 0:
                            self.vars[target.name] = 0 - eval_unknown

                        # c == (x+l) * r
                        # l == c * r^(-1) - x
                        else:
                            self.vars[target.name] = (
                                left * pow(eval_known, -1, self.p) % self.p
                            )
                    # both of them are unassigned var, skip for now
                    elif target_l and target_r:
                        raise ValueError()

                    evaluated_right = symeval(right, self.vars, self.p)

                    assert (
                        left % self.p == evaluated_right
                    ), f"{left % self.p} != {evaluated_right}, {right}"
                else:
                    # no variable assignment, directly check if lhs == rhs hold
                    evaluated_left = symeval(left, self.vars, self.p)
                    evaluated_right = symeval(right, self.vars, self.p)

                    assert (
                        evaluated_left == evaluated_right
                    ), f"{evaluated_left} != {evaluated_right}, {constraint}"

            except ValueError:  # TODO! might better to avoid this
                skipped_constraints.append(constraint)

            except TypeError:  # TODO! might better to avoid this
                skipped_constraints.append(constraint)

        if skipped_constraints and len(skipped_constraints) == len(constraints_stack):
            # print(self.vars)
            raise ValueError(
                f"There is more than one unknown value at : {skipped_constraints[0]}"
            )

        return skipped_constraints

    def __consume_hint(self):
        for target, hint in self.hints.items():
            func, args = hint

            if target not in self.vars:
                self.vars[target] = None
                self.temp_vars.append(target)

            if self.vars[target] is None:
                evaluated_args = []
                for arg in args:
                    if isinstance(arg, Symbol) and self.vars.get(arg.name) is None:
                        break
                    elif (
                        isinstance(arg, Symbol) and self.vars.get(arg.name) is not None
                    ):
                        evaluated_args.append(self.vars[arg.name])
                    else:
                        evaluated_args.append(arg)
                else:
                    result = func(*evaluated_args)
                    self.vars[target] = int(result) % self.p

    def evaluate(self, input_values: dict, output_values: dict = None) -> bool:
        """Evaluate the constraint system with given inputs and output"""
        output_values = output_values or {}
        if len(input_values) != len(self.inputs):
            raise ValueError("Length of input values differ with input variables")

        for k, _ in self.vars.items():
            self.vars[k] = None

        for inp in self.inputs:
            if inp not in self.vars:
                self.temp_vars.append(inp)

            self.vars[inp] = input_values.get(inp, 0) % self.p

        constraints_stack = self.constraints[:]

        while True:
            self.__consume_hint()
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
                self.add_constraint(eq)

    def compile(self) -> QAP:
        """
        Compile R1CS into Quadratic Arithmetic Program (QAP)

        Returns:
            qap: QAP object of the constraint system
        """
        self.__add_dummy_constraints()
        witness = self.__get_witness_vector()

        row_length = len(self.constraints)
        col_length = len(witness)

        A = SparseArray([[]], row_length, col_length, self.p)
        B = SparseArray([[]], row_length, col_length, self.p)
        C = SparseArray([[]], row_length, col_length, self.p)

        if len(self.constraints) > 8192:
            n_job = get_n_jobs()
        else:
            n_job = 1

        result = Parallel(n_jobs=n_job)(
            delayed(consume_constraint)(row, constraint, witness, self.p)
            for row, constraint in enumerate(self.constraints)
        )

        for row in result:
            A.append(row[0])
            B.append(row[1])
            C.append(row[2])

        qap = QAP(self.p)
        qap.from_r1cs(A, B, C, len(self.public) + 1)

        return qap

    def solve(self, input_values: dict, output_value: dict = None) -> list:
        """
        Generate witness by solving the constraint system with given inputs
        (optionally, with given outputs)

        Args:
            input_values: dict mapping of input variables and values
            output_value: output value of the equation

        Returns:
            witness: tuple of (public_witness, private_witness)
        """
        self.__add_dummy_constraints()
        witness = self.__get_witness_vector()

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
        for wire in result["wires"][private_offset:]:
            cs.__add_var(wire)

        cs.set_public(outputs)
        cs.set_public(public_inputs)

        for constraint in result["constraints"]:
            cs.add_constraint(constraint)

        return cs

    def to_file(self, filepath):
        raise NotImplementedError
