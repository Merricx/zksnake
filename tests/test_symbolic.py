import pytest

from zksnake.symbolic import Symbol, symeval


@pytest.fixture
def x():
    return Symbol("x")


@pytest.fixture
def y():
    return Symbol("y")


@pytest.fixture
def z():
    return Symbol("z")


def test_symbol_arithmetic(x, y, z):

    assert (x + 3).op == "ADD"
    assert (3 + x).op == "ADD"
    assert (x - 3).op == "SUB"
    assert (3 - x).op == "SUB"
    assert (x * 3).op == "MUL"
    assert (3 * x).op == "MUL"
    assert (x / 3).op == "DIV"
    assert (3 / x).op == "DIV"

    assert (x + y).op == "ADD"
    assert (x - y).op == "SUB"
    assert (x * y).op == "MUL"
    assert (x / y).op == "DIV"

    assert (x + y + z).op == "ADD"
    assert (x + y - z).op == "SUB"
    assert ((x + y) * z).op == "MUL"
    assert ((x + y) / z).op == "DIV"


def test_symeval(x, y, z):
    v1 = Symbol("v1")
    v2 = Symbol("v2")

    p = 71

    expr = x * v1 + 5 + (-y / v2) - z
    actual_result = (3 * 2 + 5 + (-5 * pow(4, -1, p)) - 3) % p

    assert symeval(expr, {"x": 3, "v1": 2, "y": 5, "v2": 4, "z": 3}, p) == actual_result


def test_complex_equation(x, y, z):
    expr1 = 2 * x + 3 * y + (-z)
    expr2 = 8 * x * (z + 4) * y / z - 12

    assert str(expr1) == "2*x + 3*y - z"
    assert str(expr2) == "8*x*(z + 4)*y / z - 12"
