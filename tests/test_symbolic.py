import pytest
from zksnake.arithmetization import Var


@pytest.fixture
def x():
    return Var("x")


@pytest.fixture
def y():
    return Var("y")


@pytest.fixture
def z():
    return Var("z")


def test_eval(x, y, z):
    v1 = Var("v1")
    v2 = Var("v2")

    p = 71

    expr = x * v1 + 5 + (-y / v2) - z
    actual_result = (3 * 2 + 5 + (-5 * pow(4, -1, p)) - 3) % p

    assert expr.evaluate({"x": 3, "v1": 2, "y": 5, "v2": 4, "z": 3}, p) == actual_result


def test_complex_equation(x, y, z):
    expr1 = 2 * x + 3 * y + (-z)
    expr2 = 8 * x * (z + 4) * y / z - 12

    assert str(expr1) == "((x * 2 + y * 3) + -(z))"
    assert str(expr2) == "(x * 8 * (z + 4) * y / z - 12)"


def test_equation(x, y, z):

    p = 71
    eq1 = 7 == (1 * x) + (2 * y) + (4 * z)
    eq2 = z == 1337
    eq3 = x * y / z == y * x / z

    result1 = eq1.evaluate({"x": 1, "y": 1, "z": 1}, p)
    result2 = eq2.evaluate({"z": 1337}, p)
    result3 = eq3.evaluate({"x": 4, "y": 2, "z": 6}, p)

    assert result1[0] == result1[1]
    assert result2[0] == result2[1]
    assert result3[0] == result3[1]
