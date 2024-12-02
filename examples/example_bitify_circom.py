import os
from zksnake.symbolic import Symbol
from zksnake.arithmetization.r1cs import ConstraintSystem
from zksnake.groth16 import Setup, Prover, Verifier

folder = os.path.dirname(__file__)
cs = ConstraintSystem.from_file(
    folder + "/circom/num2bits.r1cs", folder + "/circom/num2bits.sym"
)

for i in range(256):
    cs.add_hint(
        lambda x, n: (x >> n) & 1, f"main.out[{i}]", args=(Symbol("main.in"), i)
    )

pub, priv = cs.solve(
    {
        "main.in": 0xDEADF00D,
    }
)

qap = cs.compile()


setup = Setup(qap)

pkey, vkey = setup.generate()

prover = Prover(qap, pkey)
verifier = Verifier(vkey)

proof = prover.prove(pub, priv)

print("Proof:", proof.to_hex())

assert verifier.verify(proof, pub)
