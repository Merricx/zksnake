from __future__ import annotations
from typing import Any, Union, Callable

from ..symbolic import Symbol, SymbolArray, Equation, get_unassigned_var, symeval

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
        
    def _consume_constraint_stack(self, constraints_stack: list):
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
                            multiplier = pow(
                                symeval(r, self.vars, self.p), -1, self.p)

                        elif not target_l and target_r:
                            target = target_r
                            coeff = coeff_r
                            left = target
                            multiplier = pow(
                                symeval(l, self.vars, self.p), -1, self.p)

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
                            (evaluated_right - diff) *
                            inv_coeff * multiplier % self.p
                        )
                        val_2 = (
                            (evaluated_right + diff) *
                            inv_coeff * multiplier % self.p
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
                            l if isinstance(l, int) else symeval(
                                l, self.vars, self.p)
                        )
                        eval_r = (
                            r if isinstance(r, int) else symeval(
                                r, self.vars, self.p)
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
        
    def _consume_hint(self):
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
                        isinstance(arg, Symbol) and self.vars.get(
                            arg.name) is not None
                    ):
                        evaluated_args.append(self.vars[arg.name])
                    else:
                        evaluated_args.append(arg)
                else:
                    result = func(*evaluated_args)
                    self.vars[target] = int(result) % self.p
        
    def evaluate(self, input_values: dict, output_values: dict = None) -> bool:
        raise NotImplementedError
    
    def compile(self):
        raise NotImplementedError
    
    def solve(self, input_values: dict, output_value: dict = None) -> list:
        raise NotImplementedError


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
    
    def evaluate(self, input_values, output_values = None):
        pass
    
    def solve(self, input_values, output_value = None):
        pass
    
    def compile(self):
        pass