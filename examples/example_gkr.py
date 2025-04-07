from zksnake.subprotocol.gkr import GKR
from zksnake.arithmetization import LayeredCircuit

circuit = LayeredCircuit(["x", "y"])
circuit.mul("x", "y", "z1")
circuit.add("x", "y", "z2")

gkr = GKR(circuit)
inputs = {"x": 3, "y": 5}
outputs, proof = gkr.prove(inputs)

assert gkr.verify(inputs, outputs, proof)
print("output:", outputs)
print("Proof is valid!")
