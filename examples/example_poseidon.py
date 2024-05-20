from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem
from zksnake.gadgets.poseidon import Poseidon
from zksnake.groth16 import Setup, Prover, Verifier

a = Symbol("a")
b = Symbol("b")
c = Symbol("c")
h = Symbol("h")

cs = ConstraintSystem([a, b, c], [h])
poseidon = Poseidon(3)
cs.add_template(poseidon("hash", {"inp0": a, "inp1": b, "inp2": c}, {"out": h}))

qap = cs.compile()

pub, priv = cs.solve(
    {
        "a": 1,
        "b": 2,
        "c": 3,
    },
    {"h": 6542985608222806190361240322586112750744169038454362455181422643027100751666},
)


setup = Setup(qap)
pkey, vkey = setup.generate()

prover = Prover(qap, pkey)
proof = prover.prove(pub, priv)
print("Proof:", proof.to_hex())

verifier = Verifier(vkey)
assert verifier.verify(proof, pub)
print("Proof is valid!")
