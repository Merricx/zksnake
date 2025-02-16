from typing import Union


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
        if not isinstance(other, Symbol) and not isinstance(other, int):
            return NotImplemented

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

        return Equation(self, other)

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


class SymbolArray:
    def __init__(self, name: str, n: int):
        if n > 1:
            self.data = [Symbol(f"{name}[{i}]") for i in range(n)]
        else:
            self.data = [Symbol(name)]

        self.name = name
        self.n = n

    def __setitem__(self, index: int, value: Symbol):
        if index >= self.n:
            raise IndexError("Index out of range")
        self.data[index] = value

    def __getitem__(self, index: Union[int, slice]):
        if isinstance(index, slice):
            return [self.data[i] for i in range(*index.indices(len(self.data)))]
        else:
            if index >= self.n:
                raise IndexError("Index out of range")
            return self.data[index]

    def __len__(self) -> int:
        return len(self.data)

    def explode(self) -> list[str]:
        return [data.name for data in self.data]


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
    if isinstance(stmt, int):
        return stmt % p

    variables = var_map
    temp_vars = {}

    stack = stmt.stack[:]
    __push_stack(stmt, stack)

    for eq in stack[::-1]:
        key, op, lhs, rhs = eq

        if isinstance(lhs, Symbol):
            if lhs.op == "VAR":
                left = (
                    variables[lhs.name] if not lhs.is_negative else -variables[lhs.name]
                )
            else:
                k = str(lhs)
                left = temp_vars[k] if not lhs.is_negative else -temp_vars[k]

            if left is None:
                raise ValueError(f"Value of {lhs} is not found in variable mapping")
        else:
            left = lhs

        if isinstance(rhs, Symbol):
            if rhs.op == "VAR":
                right = (
                    variables[rhs.name] if not rhs.is_negative else -variables[rhs.name]
                )
            else:
                k = str(rhs)
                right = temp_vars[k] if not rhs.is_negative else -temp_vars[k]

            if right is None:
                raise ValueError(f"Value of {rhs} is not found in variable mapping")
        else:
            right = rhs

        result = 0
        if op == "ADD":
            key = str(lhs + rhs)
            result = (left + right) % p
        elif op == "SUB":
            key = str(lhs - rhs)
            result = (left - right) % p
        elif op == "MUL":
            key = str(lhs * rhs)
            result = left * right % p
        elif op == "DIV":
            key = str(lhs / rhs)
            result = left * pow(right, -1, p) % p

        temp_vars[key] = result

    if str(stmt) in variables:
        return variables[str(stmt)] % p

    return temp_vars[str(stmt)] % p


def get_unassigned_var(stmt: Symbol, var_map: dict):
    """
    Get the first depth of unassigned VAR and return its coefficient

    Example:
    Given `x*3 + 5`, return `x` with `3` as coefficent
    """
    if isinstance(stmt, int):
        return None, None

    if isinstance(stmt, Symbol) and stmt.op == "VAR":
        if var_map[stmt.name] is None:
            return stmt, 1

    stack = stmt.stack[:]
    __push_stack(stmt, stack)

    coeff = 1

    first_found = None

    for eq in stack:
        _, op, lhs, rhs = eq

        if isinstance(lhs, Symbol) and lhs.op == "VAR":
            if var_map[lhs.name] is None:
                first_found = lhs
                if isinstance(rhs, int) and op == "MUL":
                    coeff = rhs

                return first_found, coeff

        if isinstance(rhs, Symbol) and rhs.op == "VAR":
            if var_map[rhs.name] is None:
                first_found = rhs
                if isinstance(lhs, int) and op == "MUL":
                    coeff = lhs

                return first_found, coeff

    if not first_found:
        coeff = None

    return first_found, coeff
