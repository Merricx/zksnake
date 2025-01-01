import os
from zksnake.arithmetization.r1cs import R1CS
from zksnake.groth16 import Setup, Prover, Verifier


folder = os.path.dirname(__file__)
cs = R1CS.from_file(
    "./tests/stub/test_poseidon.r1cs", "./tests/stub/test_poseidon.sym"
)

solution = cs.solve(
    {
        "main.a": 1,
        "main.b": 2,
        "main.c": 3,
    },
)

r1cs = R1CS(cs)
r1cs.compile()

pub, priv = r1cs.generate_witness(solution)

setup = Setup(r1cs)
pkey, vkey = setup.generate()

prover = Prover(r1cs, pkey)
proof = prover.prove(pub, priv)
print("Proof:", proof.to_hex())

verifier = Verifier(vkey)
assert verifier.verify(proof, pub)
print("Proof is valid!")
