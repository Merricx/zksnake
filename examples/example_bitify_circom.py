import os
from zksnake.arithmetization import Var
from zksnake.arithmetization.r1cs import R1CS
from zksnake.groth16 import Groth16

folder = os.path.dirname(__file__)
cs = R1CS.from_file(
    folder + "/circom/num2bits.r1cs", folder + "/circom/num2bits.sym"
)

def hint(i):
    return lambda **k: (k["main.in"] >> i) & 1

for i in range(256):
    cs.unsafe_assign(
        Var(f"main.out[{i}]"), hint(i), ("main.in", )
    )

solution = cs.solve(
    {
        "main.in": 0xDEADF00D,
    }
)

r1cs = R1CS(cs)
r1cs.compile()

pub, priv = r1cs.generate_witness(solution)

groth16 = Groth16(r1cs)
groth16.setup()

proof = groth16.prove(pub, priv)
print("Proof:", proof.to_bytes().hex())

assert groth16.verify(proof, pub)
print("Proof is valid!")
