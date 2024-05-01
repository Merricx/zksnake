from mimc import eqs
from zksnake.r1cs import ConstraintSystem

from zksnake.groth16 import Setup, Prover, Verifier

# prove that we know preimage of MiMC hash (https://eprint.iacr.org/2016/492.pdf)
# such that MiMC(secret) == h
cs = ConstraintSystem(["secret"], "h")

for eq in eqs:
    cs.add(eq)

cs.set_public('h')


public_witness, private_witness = cs.solve(
    {"secret": 0xCAFEBABE},
    10836034331151348864404271225857904702295668093178783175592599434242500183632,
)

qap = cs.compile()

setup = Setup(qap)
pkey, vkey = setup.generate()

prover = Prover(qap, pkey)
verifier = Verifier(vkey)

proof = prover.prove(public_witness, private_witness)
print("Proof:", proof.to_hex())

assert verifier.verify(proof, public_witness)
print("Proof is valid!")
