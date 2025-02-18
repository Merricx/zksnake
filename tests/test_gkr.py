import pytest, random

from zksnake.constant import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD
from zksnake.subprotocol.gkr import GKR, LayeredCircuit

@pytest.fixture
def circuit_data():

    circuit1 = LayeredCircuit(['x', 'y'])
    circuit1.add_gate('ADD', 'x', 'y', 'z')
    circuit1.add_layer()
    circuit1.add_gate('MUL', 'z', 'z', 'zz')

    circuit2 = LayeredCircuit(['x', 'y', 'u', 'v'])
    circuit2.add_gate('ADD', 'x', 'y', 'z1')
    circuit2.add_gate('MUL', 'x', 'y', 'z2')
    circuit2.add_gate('MUL', 'x', 'y', 'z3')
    circuit2.add_gate('MUL', 'u', 'v', 'w')
    circuit2.add_layer()
    circuit2.add_gate('MUL', 'z1', 'z2', 'zz')
    circuit2.add_gate('MUL', 'z1', 'z3', 'zzz')
    circuit2.add_gate('MUL', 'w', 'w', 'ww')
    circuit2.add_layer()
    circuit2.add_gate('ADD', 'zzz', 'zz', 'a')
    circuit2.add_gate('MUL', 'zzz', 'ww', 'b')

    circuit3 = LayeredCircuit(['a1', 'a2', 'a3', 'a4'])
    circuit3.add_gate('MUL', 'a1', 'a1', 'b1')
    circuit3.add_gate('MUL', 'a2', 'a2', 'b2')
    circuit3.add_gate('MUL', 'a2', 'a3', 'b3')
    circuit3.add_gate('MUL', 'a4', 'a4', 'b4')
    circuit3.add_layer()
    circuit3.add_gate('MUL', 'b1', 'b2', 'c1')
    circuit3.add_gate('MUL', 'b3', 'b4', 'c2')

    return [circuit1, circuit2, circuit3]

def test_e2e_gkr_bn254(circuit_data):

    random.seed('gkr')
    for circuit in circuit_data:

        gkr = GKR(circuit)
        inp = {}
        for key in circuit.inputs:
            inp[key] = random.randrange(1, BN254_SCALAR_FIELD - 1)

        output, proof = gkr.prove(inp)

        assert gkr.verify(inp, output, proof)

def test_e2e_gkr_bls12_381(circuit_data):

    random.seed('gkr')
    for circuit in circuit_data:

        gkr = GKR(circuit, BLS12_381_SCALAR_FIELD)
        inp = {}
        for key in circuit.inputs:
            inp[key] = random.randrange(1, BLS12_381_SCALAR_FIELD - 1)

        output, proof = gkr.prove(inp)

        assert gkr.verify(inp, output, proof)
