
class Symbol:
    def __init__(self, name):
        self.name = name
        self.left = None
        self.right = None
        self.op = "VAR"
        self.is_negative = False
    
    def __str__(self):
        return f"(-{self.name})" if self.is_negative else self.name
    
    def __repr__(self):
        return self.__str__()
    
    def __eq__(self, other):
        if isinstance(self, Symbol) and self.op in ['VAR']:
            return Equation(self, other)
        elif isinstance(other, Symbol) and other.op in ['VAR']:
            return Equation(other, self)
        elif isinstance(self, Symbol) and self.op in ['ADD', 'SUB'] and isinstance(other, Symbol) and other.op in ['MUL', 'DIV']:
            return Equation(self, other)
        elif isinstance(self, Symbol) and other.op in ['ADD', 'SUB'] and isinstance(self, Symbol) and self.op in ['MUL', 'DIV']:
            return Equation(other, self)
        else:
            raise ValueError("Invalid constraint")
    
    def __add__(self, other):
        return Add(self, other)
    
    def __radd__(self, other):
        return Add(other, self)
    
    def __sub__(self, other):
        return Subtract(self, other)
    
    def __rsub__(self, other):
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
        raise NotImplementedError("Integer power is not supported. Consider converting power to multiplication.")


class Add(Symbol):
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.op = "ADD"
    
    def __str__(self):
        is_left_root = isinstance(self.left, int) or (isinstance(self.left, Symbol) and self.left.op == 'VAR')
        is_right_root = isinstance(self.right, int) or (isinstance(self.right, Symbol) and self.right.op == 'VAR')
        
        s = f"{self.left} + {self.right}"
        if is_left_root and is_right_root:
            s = f"({s})"
        
        return s
    
    
class Subtract(Symbol):
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.op = "SUB"
    
    def __str__(self):
        is_left_root = isinstance(self.left, int) or (isinstance(self.left, Symbol) and self.left.op == 'VAR')
        is_right_root = isinstance(self.right, int) or (isinstance(self.right, Symbol) and self.right.op == 'VAR')
        
        s = f"{self.left} - {self.right}"
        if is_left_root and is_right_root:
            s = f"({s})"
        
        return s

class Multiply(Symbol):
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.op = "MUL"

        if isinstance(left, Symbol) and isinstance(right, int):
            self.left, self.right = self.right, self.left
    
    def __str__(self):
        return f"{self.left}*{self.right}"
    
    
class Divide(Symbol):
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.op = "DIV"
    
    def __str__(self):
        return f"{self.left} / {self.right}"

class Equation(Symbol):
    def __init__(self, left, right):
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