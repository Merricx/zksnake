from __future__ import annotations
from typing import Any, Union, Callable

from ..symbolic import Symbol, SymbolArray, Equation

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