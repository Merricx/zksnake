import time
from mimc import eqs
from zksnake.r1cs import ConstraintSystem

from zksnake.groth16 import Setup, Prover, Verifier

# prove that we know preimage of MiMC hash (https://eprint.iacr.org/2016/492.pdf)
# such that MiMC(secret) == h
cs = ConstraintSystem(["secret"], ["h"])

for eq in eqs:
    cs.add_constraint(eq)

cs.set_public("h")


public_witness, private_witness = cs.solve(
    {"secret": 0xCAFEBABE},
    {
        "h": 10836034331151348864404271225857904702295668093178783175592599434242500183632
    },
)

st = time.time()
qap = cs.compile()
print(time.time() - st)

setup = Setup(qap)
st = time.time()
pkey, vkey = setup.generate()
print(time.time() - st)

prover = Prover(qap, pkey)
verifier = Verifier(vkey)

st = time.time()
proof = prover.prove(public_witness, private_witness)
print(time.time() - st)
print("Proof:", proof.to_hex())

st = time.time()
assert verifier.verify(proof, public_witness)
print(time.time() - st)
print("Proof is valid!")
