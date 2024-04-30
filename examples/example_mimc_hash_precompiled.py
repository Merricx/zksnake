import json

from mimc import eqs, h
from zksnake.r1cs import ConstraintSystem

from zksnake.groth16 import Setup, Prover, Verifier

if __name__ == "__main__":

    cs = ConstraintSystem(["secret"], "h")

    for eq in eqs:
        cs.add(eq)

    cs.set_public(h)

    public_witness, private_witness = cs.solve(
        {"secret": 0xDEADF00D},
        1037254799353855871006189384309576393135431139055333626960622147300727796413,
    )

    qap = cs.compile()

    compiled = {"U": qap.U, "V": qap.V, "W": qap.W, "T": qap.T.coeffs()}
    open("compiled_mimc.json", "w").write(json.dumps(compiled))

    setup = Setup(qap)

    pkey, vkey = setup.generate()

    prover = Prover(qap, pkey)
    verifier = Verifier(vkey)

    proof = prover.prove(public_witness, private_witness)

    print("Proof:", proof.to_hex())

    assert verifier.verify(proof, public_witness)
    print("Proof is valid!")
