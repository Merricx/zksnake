import pytest
from zksnake.gadgets import cmp, bitify, bitwise
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem


@pytest.fixture
def constraint_data():
    return [
        {"x": 1337, "y": 12345},
        {"x": 12345, "y": 1337},
        {"x": 100, "y": 0},
    ]


def test_bit_conversion():

    x = Symbol("x")
    n_bit = 16

    n2b_16bit = bitify.NumToBits(n_bit)
    b2n_16bit = bitify.BitsToNum(n_bit)

    bits = []
    outputs = {}
    for i in range(n_bit):
        v = Symbol(f"bit{i}")
        bits.append(v)
        outputs[f"bit{i}"] = v

    cs = ConstraintSystem([x], bits)

    cs.add_template(n2b_16bit("n2b", {"inp": x}, outputs))

    cs.evaluate({"x": 1337})

    expected_bits = bin(1337)[2:].zfill(n_bit)[::-1]
    for i in range(n_bit):
        assert cs.vars[f"bit{i}"] == int(expected_bits[i])

    out = Symbol("out")
    cs = ConstraintSystem(bits, ["out"])
    cs.add_template(b2n_16bit("b2n", outputs, {"out": out}))

    bit_input = {}
    for i in range(n_bit):
        bit_input[f"bit{i}"] = int(expected_bits[i])

    cs.evaluate(bit_input)
    assert cs.vars["out"] == 1337


def test_bitwise(constraint_data):

    x = Symbol("x")
    y = Symbol("y")
    out = Symbol("out")

    # AND operation
    cs = ConstraintSystem([x, y], [out])
    and_template = bitwise.And(16)
    cs.add_template(and_template("and", {"inp1": x, "inp2": y}, {"out": out}))
    for data in constraint_data:
        cs.evaluate(data)
        assert cs.vars["out"] == data["x"] & data["y"]

    # OR operation
    cs = ConstraintSystem([x, y], [out])
    or_template = bitwise.Or(16)
    cs.add_template(or_template("or", {"inp1": x, "inp2": y}, {"out": out}))
    for data in constraint_data:
        cs.evaluate(data)
        assert cs.vars["out"] == data["x"] | data["y"]

    # XOR operation
    cs = ConstraintSystem([x, y], [out])
    xor_template = bitwise.Xor(16)
    cs.add_template(xor_template("xor", {"inp1": x, "inp2": y}, {"out": out}))
    for data in constraint_data:
        cs.evaluate(data)
        assert cs.vars["out"] == data["x"] ^ data["y"]

    # NOT operation
    cs = ConstraintSystem([x], [out])
    not_template = bitwise.Not(16)
    cs.add_template(not_template("note", {"inp": x}, {"out": out}))
    for data in constraint_data:
        cs.evaluate({"x": data["x"]})
        assert cs.vars["out"] == (~data["x"]) % 2**16

    # NAND operation
    cs = ConstraintSystem([x, y], [out])
    nand_template = bitwise.Nand(16)
    cs.add_template(nand_template("nand", {"inp1": x, "inp2": y}, {"out": out}))
    for data in constraint_data:
        cs.evaluate(data)
        assert cs.vars["out"] == (~(data["x"] & data["y"])) % 2**16

    # NOR operation
    cs = ConstraintSystem([x, y], [out])
    nor_template = bitwise.Nor(16)
    cs.add_template(nor_template("nor", {"inp1": x, "inp2": y}, {"out": out}))
    for data in constraint_data:
        cs.evaluate(data)
        assert cs.vars["out"] == (~(data["x"] | data["y"])) % 2**16


def test_cmp():

    x = Symbol("x")
    y = Symbol("y")
    out = Symbol("out")

    cs = ConstraintSystem([x, y], [out])
    is_zero = cmp.IsEqual(cs.p)
    cs.add_template(is_zero("is_zero", {"inp1": x, "inp2": y}, {"out": out}))

    cs.evaluate({"x": 13337, "y": 13330}, {"out": 0})
    cs.evaluate({"x": 13337, "y": 13337}, {"out": 1})
    cs.evaluate({"x": -1, "y": 1}, {"out": 0})
    cs.evaluate({"x": cs.p - 1, "y": -1}, {"out": 1})
    cs.evaluate({"x": 0, "y": 0}, {"out": 1})
    cs.evaluate({"x": -578, "y": -578}, {"out": 1})

    cs = ConstraintSystem([x, y], [out])
    gt = cmp.GreaterThan(16)
    cs.add_template(gt("gt", {"inp1": x, "inp2": y}, {"out": out}))

    cs.evaluate({"x": 13330, "y": 13337}, {"out": 0})
    cs.evaluate({"x": 13337, "y": 13330}, {"out": 1})
    cs.evaluate({"x": 1, "y": -1}, {"out": 1})
    cs.evaluate({"x": 0, "y": 0}, {"out": 0})

    cs = ConstraintSystem([x, y], [out])
    gte = cmp.GreaterEqThan(16)
    cs.add_template(gte("gte", {"inp1": x, "inp2": y}, {"out": out}))

    cs.evaluate({"x": 13337, "y": 13337}, {"out": 1})
    cs.evaluate({"x": 13338, "y": 13337}, {"out": 1})
    cs.evaluate({"x": 13330, "y": 13337}, {"out": 0})
    cs.evaluate({"x": -1, "y": 1}, {"out": 0})
    cs.evaluate({"x": 0, "y": 0}, {"out": 1})
