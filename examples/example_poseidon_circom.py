import os
from zksnake.r1cs import ConstraintSystem
from zksnake.groth16 import Setup, Prover, Verifier


folder = os.path.dirname(__file__)
cs = ConstraintSystem.from_file(
    folder + "/circom/poseidon.r1cs", folder + "/circom/poseidon.sym"
)
qap = cs.compile()

pub, priv = cs.solve(
    {
        "main.a": 1,
        "main.b": 2,
        "main.c": 3,
    },
    {
        "main.h": 6542985608222806190361240322586112750744169038454362455181422643027100751666
    },
)


setup = Setup(qap)
pkey, vkey = setup.generate()

prover = Prover(qap, pkey)
proof = prover.prove(pub, priv)
print("Proof:", proof.to_hex())

verifier = Verifier(vkey)
assert verifier.verify(proof, pub)
print("Proof is valid!")
