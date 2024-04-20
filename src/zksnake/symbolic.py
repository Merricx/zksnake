from copy import deepcopy


class Symbol:

    def __init__(self, name):
        self.name = name
        self.left = None
        self.right = None
        self.op = "VAR"
        self.is_negative = False
        self.stack = []

    def __str__(self):
        return f"(-{self.name})" if self.is_negative else self.name

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if isinstance(self, Symbol) and self.op in ["VAR"]:
            return Equation(self, other)
        if isinstance(other, Symbol) and other.op in ["VAR"]:
            return Equation(other, self)
        if (
            isinstance(self, Symbol)
            and self.op in ["ADD", "SUB"]
            and isinstance(other, Symbol)
            and other.op in ["MUL", "DIV"]
        ):
            return Equation(self, other)
        if (
            isinstance(other, Symbol)
            and other.op in ["ADD", "SUB"]
            and isinstance(self, Symbol)
            and self.op in ["MUL", "DIV"]
        ):
            return Equation(other, self)
        if isinstance(self, Symbol) and isinstance(other, int):
            return Equation(other, self)

        raise ValueError("Invalid constraint")

    def __add__(self, other):
        if isinstance(other, Symbol) and other.is_negative:
            other.is_negative = False
            return Subtract(self, other)

        return Add(self, other)

    def __radd__(self, other):
        if isinstance(self, Symbol) and self.is_negative:
            self.is_negative = False
            return Subtract(other, self)

        return Add(other, self)

    def __sub__(self, other):
        if isinstance(other, Symbol) and other.is_negative:
            other.is_negative = False
            return Add(self, other)

        return Subtract(self, other)

    def __rsub__(self, other):
        if isinstance(self, Symbol) and self.is_negative:
            self.is_negative = False
            return Add(other, self)

        return Subtract(other, self)

    def __neg__(self):
        self.is_negative = False if self.is_negative else True
        return self

    def __mul__(self, other):
        return Multiply(self, other)

    def __rmul__(self, other):
        return Multiply(other, self)

    def __truediv__(self, other):
        return Divide(self, other)

    def __rtruediv__(self, other):
        return Divide(other, self)

    def __floordiv__(self, other):
        return Divide(self, other)

    def __rfloordiv__(self, other):
        return Divide(self, other)

    def __pow__(self, other):
        raise SyntaxError(
            "Integer power is not supported. Consider converting power to multiplication."
        )

    def __bitwise_error(self):
        raise SyntaxError("Only arithmetic operation allowed in this context")

    def __compare_error(self):
        raise SyntaxError("Only equality operator allowed in this context")

    def __lt__(self, other):
        self.__compare_error()

    def __gt__(self, other):
        self.__compare_error()

    def __le__(self, other):
        self.__compare_error()

    def __ge__(self, other):
        self.__compare_error()

    def __ne__(self, other):
        self.__compare_error()

    def __and__(self, other):
        self.__bitwise_error()

    def __or__(self, other):
        self.__bitwise_error()

    def __xor__(self, other):
        self.__bitwise_error()

    def __lshift__(self, other):
        self.__bitwise_error()

    def __rshift__(self, other):
        self.__bitwise_error()

    def __invert__(self):
        self.__bitwise_error()


class Add(Symbol):
    def __init__(self, left, right):
        super().__init__("")
        self.left = left
        self.right = right
        self.op = "ADD"
        self.stack = [(self.__str__(), self.op, left, right)]

    def __str__(self):
        is_left_root = isinstance(self.left, int) or (
            isinstance(self.left, Symbol) and self.left.op == "VAR"
        )
        is_right_root = isinstance(self.right, int) or (
            isinstance(self.right, Symbol) and self.right.op == "VAR"
        )

        s = f"{self.left} + {self.right}"
        if is_left_root and is_right_root:
            s = f"({s})"

        return s


class Subtract(Symbol):
    def __init__(self, left, right):
        super().__init__("")
        self.left = left
        self.right = right
        self.op = "SUB"
        self.stack = [(self.__str__(), self.op, left, right)]

    def __str__(self):
        is_left_root = isinstance(self.left, int) or (
            isinstance(self.left, Symbol) and self.left.op == "VAR"
        )
        is_right_root = isinstance(self.right, int) or (
            isinstance(self.right, Symbol) and self.right.op == "VAR"
        )

        s = f"{self.left} - {self.right}"
        if is_left_root and is_right_root:
            s = f"({s})"

        return s


class Multiply(Symbol):
    def __init__(self, left, right):
        super().__init__("")
        self.left = left
        self.right = right
        self.op = "MUL"

        if isinstance(left, Symbol) and isinstance(right, int):
            self.left, self.right = self.right, self.left

        self.stack = [(self.__str__(), self.op, self.left, self.right)]

    def __str__(self):
        return f"{self.left}*{self.right}"


class Divide(Symbol):
    def __init__(self, left, right):
        super().__init__("")
        self.left = left
        self.right = right
        self.op = "DIV"
        self.stack = [(self.__str__(), self.op, left, right)]

    def __str__(self):
        if self.is_negative:
            return f"-({self.left} / {self.right})"
        return f"{self.left} / {self.right}"


class Equation(Symbol):
    def __init__(self, left, right):
        super().__init__("")
        self.left = left
        self.right = right
        self.op = "EQ"

    def __str__(self):
        return f"{self.left} = {self.right}"

    def __add__(self, other):
        raise ValueError("Equation cannot be added")

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        raise ValueError("Equation cannot be subtracted")

    def __rsub__(self, other):
        return self.__sub__(other)

    def __mul__(self, other):
        raise ValueError("Equation cannot be multiplied")

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        raise ValueError("Equation cannot be divided")

    def __rtruediv__(self, other):
        return self.__truediv__(other)

    def __floordiv__(self, other):
        return self.__truediv__(other)

    def __rfloordiv__(self, other):
        return self.__truediv__(other)

    def __neg__(self):
        raise NotImplementedError()


def __push_stack(eq, stack):
    left = eq.left
    right = eq.right

    if isinstance(left, Symbol):
        if left.stack:
            stack += left.stack
        __push_stack(left, stack)

    if isinstance(right, Symbol):
        if right.stack:
            stack += right.stack
        __push_stack(right, stack)


def symeval(stmt: Symbol, var_map: dict, p: int):
    """
    Literal eval of Symbol object. `var_map` must be provided
    with all variables defined in the equation.

    Args:
        stmt: Symbol equation to be evaluated
        var_map: Key-value mapping of all variables defined in the Symbol.
        Non-mapped variable will raise IndexError.
        p: Prime modulus to be used in the arithmetic operation
    """
    variables = deepcopy(var_map)

    stack = stmt.stack[:]
    __push_stack(stmt, stack)

    for eq in stack[::-1]:
        key, op, lhs, rhs = eq

        if isinstance(lhs, Symbol):
            k = lhs.name if lhs.op == "VAR" else str(lhs)
            left = variables[k] if not lhs.is_negative else -variables[k]

            if left is None:
                raise ValueError(f"Value of {lhs} is not found in variable mapping")
        else:
            left = lhs

        if isinstance(rhs, Symbol):
            k = rhs.name if rhs.op == "VAR" else str(rhs)
            right = variables[k] if not rhs.is_negative else -variables[k]

            if right is None:
                raise ValueError(f"Value of {lhs} is not found in variable mapping")
        else:
            right = rhs

        result = 0
        if op == "ADD":
            result = (left + right) % p
        elif op == "SUB":
            result = (left - right) % p
        elif op == "MUL":
            result = left * right % p
        elif op == "DIV":
            result = left * pow(right, -1, p) % p

        variables[key] = result

    return variables[str(stmt)]
