# import pytest
# from zksnake.gadgets import cmp, bitify, bitwise, binsum
# from zksnake.gadgets.hash import poseidon
# from zksnake.symbolic import Symbol, SymbolArray
# from zksnake.arithmetization.r1cs import ConstraintSystem


# @pytest.fixture
# def constraint_data():
#     return [
#         {"x": 1337, "y": 12345},
#         {"x": 12345, "y": 1337},
#         {"x": 100, "y": 0},
#     ]


# @pytest.fixture
# def poseidon_test_vector():

#     return [
#         # test vector from https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master
#         {
#             # poseidonperm_x5_254_3
#             "n_input": 2,
#             "inputs": [1, 2],
#             "expected": 0x115CC0F5E7D690413DF64C6B9662E9CF2A3617F2743245519E19607A4417189A,
#         },
#         {
#             # poseidonperm_x5_254_5
#             "n_input": 4,
#             "inputs": [1, 2, 3, 4],
#             "expected": 0x299C867DB6C1FDD79DCEFA40E4510B9837E60EBB1CE0663DBAA525DF65250465,
#         },
#         # test vector from https://github.com/iden3/circomlib/blob/master/test/poseidoncircuit.js
#         {
#             "n_input": 2,
#             "inputs": [3, 4],
#             "expected": 14763215145315200506921711489642608356394854266165572616578112107564877678998,
#         },
#         {
#             "n_input": 5,
#             "inputs": [1, 2, 0, 0, 0],
#             "expected": 1018317224307729531995786483840663576608797660851238720571059489595066344487,
#         },
#         {
#             "n_input": 5,
#             "inputs": [3, 4, 5, 10, 23],
#             "expected": 13034429309846638789535561449942021891039729847501137143363028890275222221409,
#         },
#     ]


# def test_bit_conversion():

#     x = Symbol("x")
#     n_bit = 16

#     n2b_16bit = bitify.NumToBits(n_bit)
#     b2n_16bit = bitify.BitsToNum(n_bit)

#     bits = SymbolArray("bit", n_bit)

#     cs = ConstraintSystem([x], bits.explode())

#     cs.add_template(bits == n2b_16bit("n2b", x))

#     cs.evaluate({"x": 1337})

#     expected_bits = bin(1337)[2:].zfill(n_bit)[::-1]
#     for i in range(n_bit):
#         assert cs.vars[f"bit[{i}]"] == int(expected_bits[i])

#     out = Symbol("out")
#     cs = ConstraintSystem(bits.explode(), ["out"])
#     cs.add_template(out == b2n_16bit("b2n", bits))

#     bit_input = {}
#     for i in range(n_bit):
#         bit_input[f"bit[{i}]"] = int(expected_bits[i])

#     cs.evaluate(bit_input)
#     assert cs.vars["out"] == 1337


# def test_bitwise(constraint_data):

#     x = Symbol("x")
#     y = Symbol("y")
#     out = Symbol("out")

#     # AND operation
#     cs = ConstraintSystem([x, y], [out])
#     and_template = bitwise.And(16)
#     cs.add_template(out == and_template("and", x, y))
#     for data in constraint_data:
#         cs.evaluate(data)
#         assert cs.vars["out"] == data["x"] & data["y"]

#     # OR operation
#     cs = ConstraintSystem([x, y], [out])
#     or_template = bitwise.Or(16)
#     cs.add_template(out == or_template("or", x, y))
#     for data in constraint_data:
#         cs.evaluate(data)
#         assert cs.vars["out"] == data["x"] | data["y"]

#     # XOR operation
#     cs = ConstraintSystem([x, y], [out])
#     xor_template = bitwise.Xor(16)
#     cs.add_template(out == xor_template("xor", x, y))
#     for data in constraint_data:
#         cs.evaluate(data)
#         assert cs.vars["out"] == data["x"] ^ data["y"]

#     # NOT operation
#     cs = ConstraintSystem([x], [out])
#     not_template = bitwise.Not(16)
#     cs.add_template(out == not_template("note", x))
#     for data in constraint_data:
#         cs.evaluate({"x": data["x"]})
#         assert cs.vars["out"] == (~data["x"]) % 2**16

#     # NAND operation
#     cs = ConstraintSystem([x, y], [out])
#     nand_template = bitwise.Nand(16)
#     cs.add_template(out == nand_template("nand", x, y))
#     for data in constraint_data:
#         cs.evaluate(data)
#         assert cs.vars["out"] == (~(data["x"] & data["y"])) % 2**16

#     # NOR operation
#     cs = ConstraintSystem([x, y], [out])
#     nor_template = bitwise.Nor(16)
#     cs.add_template(out == nor_template("nor", x, y))
#     for data in constraint_data:
#         cs.evaluate(data)
#         assert cs.vars["out"] == (~(data["x"] | data["y"])) % 2**16


# def test_cmp():

#     x = Symbol("x")
#     y = Symbol("y")
#     out = Symbol("out")

#     cs = ConstraintSystem([x, y], [out])
#     is_zero = cmp.IsEqual(cs.p)
#     cs.add_template(out == is_zero("is_zero", x, y))

#     cs.evaluate({"x": 13337, "y": 13330}, {"out": 0})
#     cs.evaluate({"x": 13337, "y": 13337}, {"out": 1})
#     cs.evaluate({"x": -1, "y": 1}, {"out": 0})
#     cs.evaluate({"x": cs.p - 1, "y": -1}, {"out": 1})
#     cs.evaluate({"x": 0, "y": 0}, {"out": 1})
#     cs.evaluate({"x": -578, "y": -578}, {"out": 1})

#     cs = ConstraintSystem([x, y], [out])
#     gt = cmp.GreaterThan(16)
#     cs.add_template(out == gt("gt", x, y))

#     cs.evaluate({"x": 13330, "y": 13337}, {"out": 0})
#     cs.evaluate({"x": 13337, "y": 13330}, {"out": 1})
#     cs.evaluate({"x": 1, "y": -1}, {"out": 1})
#     cs.evaluate({"x": 0, "y": 0}, {"out": 0})

#     cs = ConstraintSystem([x, y], [out])
#     gte = cmp.GreaterEqThan(16)
#     cs.add_template(out == gte("gte", x, y))

#     cs.evaluate({"x": 13337, "y": 13337}, {"out": 1})
#     cs.evaluate({"x": 13338, "y": 13337}, {"out": 1})
#     cs.evaluate({"x": 13330, "y": 13337}, {"out": 0})
#     cs.evaluate({"x": -1, "y": 1}, {"out": 0})
#     cs.evaluate({"x": 0, "y": 0}, {"out": 1})


# def test_poseidon(poseidon_test_vector):

#     for test_vector in poseidon_test_vector:
#         n_input = test_vector["n_input"]
#         inputs = test_vector["inputs"]
#         expected = test_vector["expected"]

#         sym_inputs = SymbolArray("v", n_input)
#         out = SymbolArray("out", 1)

#         poseidon_eval = {}
#         for i in range(n_input):
#             poseidon_eval[f"v[{i}]"] = inputs[i]

#         cs = ConstraintSystem([sym_inputs], [out])
#         poseidon_hash = poseidon.Poseidon(n_input)

#         cs.add_template(out == poseidon_hash("hash", sym_inputs))

#         cs.evaluate(poseidon_eval, {"out": expected})


# def test_binsum():

#     ops = 3
#     n_bit = 8
#     inp = []
#     for i in range(ops):
#         inp.append(SymbolArray(f"inp[{i}]", n_bit))

#     out = SymbolArray("out", binsum.nbits((2**n_bit - 1) * ops))

#     cs = ConstraintSystem(inp, [out])

#     bsum = binsum.BinSum(n_bit, ops)

#     cs.add_template(out == bsum("sum", inp))

#     for x, y, z in [(0, 1, 3), (7, 20, 12), (255, 255, 255)]:

#         vals = [x, y, z]

#         eval_input = {}
#         for i in range(ops):
#             for j in range(n_bit):
#                 eval_input[f"inp[{i}][{j}]"] = (vals[i] >> j) & 1

#         cs.evaluate(eval_input)

#         expected_bits = bin(x + y + z)[2:].zfill(n_bit)[::-1]
#         for i in range(n_bit):
#             assert cs.vars[f"out[{i}]"] == int(expected_bits[i])
