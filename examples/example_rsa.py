from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem

from zksnake.groth16 import Setup, Prover, Verifier

p = Symbol("p")
q = Symbol("q")
v0 = Symbol("v0")
v1 = Symbol("v1")
v2 = Symbol("v2")
n = Symbol("n")

# prove that we know p and q such that n == p*q
cs = ConstraintSystem(["p", "q"], ["n"])
cs.add(v0 == 1 / (p - 1))  # make sure p != 1
cs.add(v1 == 1 / (q - 1))  # make sure q != 1
cs.add(v2 == p * q)
cs.add(n == v2)

cs.set_public(n)  # value of n is public knowledge

qap = cs.compile()

pval = 64135289477071580278790190170577389084825014742943447208116859632024532344630238623598752668347708737661925585694639798853367
qval = 33372027594978156556226010605355114227940760344767554666784520987023841729210037080257448673296881877565718986258036932062711
nval = 2140324650240744961264423072839333563008614715144755017797754920881418023447140136643345519095804679610992851872470914587687396261921557363047454770520805119056493106687691590019759405693457452230589325976697471681738069364894699871578494975937497937

assert pval * qval == nval

public_witness, private_witness = cs.solve({"p": pval, "q": qval}, {"n": nval})

setup = Setup(qap)

pkey, vkey = setup.generate()

prover = Prover(qap, pkey)
verifier = Verifier(vkey)

proof = prover.prove(public_witness, private_witness)

print("Proof:", proof.to_hex())

assert verifier.verify(proof, public_witness)
print("Proof is valid!")
