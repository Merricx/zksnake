import pytest
from zksnake.gadgets import cmp, bitify, bitwise, poseidon
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem


@pytest.fixture
def constraint_data():
    return [
        {"x": 1337, "y": 12345},
        {"x": 12345, "y": 1337},
        {"x": 100, "y": 0},
    ]


@pytest.fixture
def poseidon_test_vector():
    # test vector from https://github.com/iden3/circomlib/blob/master/test/poseidoncircuit.js
    return [
        {
            "n_input": 2,
            "inputs": [1, 2],
            "expected": 7853200120776062878684798364095072458815029376092732009249414926327459813530,
        },
        {
            "n_input": 2,
            "inputs": [3, 4],
            "expected": 14763215145315200506921711489642608356394854266165572616578112107564877678998,
        },
        {
            "n_input": 5,
            "inputs": [1, 2, 0, 0, 0],
            "expected": 1018317224307729531995786483840663576608797660851238720571059489595066344487,
        },
        {
            "n_input": 5,
            "inputs": [3, 4, 5, 10, 23],
            "expected": 13034429309846638789535561449942021891039729847501137143363028890275222221409,
        },
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


def test_poseidon(poseidon_test_vector):

    for test_vector in poseidon_test_vector:
        n_input = test_vector["n_input"]
        inputs = test_vector["inputs"]
        expected = test_vector["expected"]

        sym_inputs = []
        poseidon_input = {}
        poseidon_eval = {}
        for i in range(n_input):
            sym_inputs.append(Symbol(f"v{i}"))
            poseidon_input[f"inp{i}"] = sym_inputs[i]
            poseidon_eval[f"v{i}"] = inputs[i]

        out = Symbol("out")

        cs = ConstraintSystem(sym_inputs, [out])
        poseidon_hash = poseidon.Poseidon(n_input)

        cs.add_template(poseidon_hash("hash", poseidon_input, {"out": out}))

        cs.evaluate(poseidon_eval, {"out": expected})
