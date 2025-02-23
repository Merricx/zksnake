import os
from zksnake.arithmetization.r1cs import R1CS
from zksnake.groth16 import Groth16


folder = os.path.dirname(__file__)
r1cs = R1CS.from_file(
    folder + "/circom/poseidon.r1cs", folder + "/circom/poseidon.sym"
)

solution = r1cs.constraint_system.solve(
    {
        "main.a": 1,
        "main.b": 2,
        "main.c": 3,
    },
)

r1cs.compile()

pub, priv = r1cs.generate_witness(solution)

groth16 = Groth16(r1cs)
groth16.setup()

proof = groth16.prove(pub, priv)
print("Proof:", proof.to_bytes().hex())

assert groth16.verify(proof, pub)
print("Proof is valid!")
