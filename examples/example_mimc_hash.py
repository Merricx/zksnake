import os
import json
import time
from mimc import eqs, h
from zksnake.r1cs import ConstraintSystem
from zksnake.qap import QAP
from zksnake.optimized_polynomial import PolynomialRing

from zksnake.groth16.setup import Setup
from zksnake.groth16.prover import Prover
from zksnake.groth16.verifier import Verifier


cs = ConstraintSystem(["secret"], "h")

for eq in eqs:
    cs.add(eq)

cs.set_public(h)

public_witness, private_witness = cs.solve(
    {"secret": 0xDEADF00D},
    1037254799353855871006189384309576393135431139055333626960622147300727796413,
)
folder = os.path.dirname(__file__)
qap_json = open(folder + "/compiled_mimc.json", "r").read()
qap_data = json.loads(qap_json)

qap = QAP(cs.p)
qap.U = qap_data["U"]
qap.V = qap_data["V"]
qap.W = qap_data["W"]
qap.T = PolynomialRing(qap_data["T"], cs.p)
qap.n_public = len(public_witness)


setup = Setup(qap)
pkey, vkey = setup.generate()

prover = Prover(qap, pkey)
verifier = Verifier(vkey)

start = time.time()
proof = prover.prove(public_witness, private_witness)
end = time.time() - start
print(f"Prove time: {end}s")
print("Proof:", proof.to_hex())

start = time.time()
assert verifier.verify(proof, public_witness)
end = time.time() - start
print(f"Verify time: {end}s")
print("Proof is valid!")
