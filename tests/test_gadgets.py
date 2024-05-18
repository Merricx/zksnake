import pytest
from zksnake.gadgets import IsEqual, GreaterThan, GreaterEqThan, Bitify
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem


def test_bit_operation():

    x = Symbol("x")
    y = Symbol("y")
    out = Symbol("out")

    pass


def test_cmp():

    x = Symbol("x")
    y = Symbol("y")
    out = Symbol("out")

    cs = ConstraintSystem([x, y], [out])
    is_zero = IsEqual(cs.p)
    cs.add_template(is_zero({"inp1": x, "inp2": y}, {"out": out}))

    cs.evaluate({"x": 13337, "y": 13330}, {"out": 0})
    cs.evaluate({"x": 13337, "y": 13337}, {"out": 1})
    cs.evaluate({"x": -1, "y": 1}, {"out": 0})
    cs.evaluate({"x": cs.p - 1, "y": -1}, {"out": 1})
    cs.evaluate({"x": 0, "y": 0}, {"out": 1})
    cs.evaluate({"x": -578, "y": -578}, {"out": 1})

    cs = ConstraintSystem([x, y], [out])
    gt = GreaterThan(16)
    cs.add_template(gt({"inp1": x, "inp2": y}, {"out": out}))

    cs.evaluate({"x": 13330, "y": 13337}, {"out": 0})
    cs.evaluate({"x": 13337, "y": 13330}, {"out": 1})
    cs.evaluate({"x": 1, "y": -1}, {"out": 1})
    cs.evaluate({"x": 0, "y": 0}, {"out": 0})

    cs = ConstraintSystem([x, y], [out])
    gte = GreaterEqThan(16)
    cs.add_template(gte({"inp1": x, "inp2": y}, {"out": out}))

    cs.evaluate({"x": 13337, "y": 13337}, {"out": 1})
    cs.evaluate({"x": 13338, "y": 13337}, {"out": 1})
    cs.evaluate({"x": 13330, "y": 13337}, {"out": 0})
    cs.evaluate({"x": -1, "y": 1}, {"out": 0})
    cs.evaluate({"x": 0, "y": 0}, {"out": 1})
