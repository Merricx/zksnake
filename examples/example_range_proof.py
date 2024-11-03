"""
Prove that v is in range of [0, 2^32-1] without revealing the value of v itself
using Inner Product Argument (Bulletproofs)
"""
from zksnake.bulletproofs.range_proof import Prover, Verifier

bitsize = 32
prover = Prover(bitsize, 'BN254')

# secret value v
value = 133337

proof, commitment = prover.prove(value)
print("Proof:", proof.to_bytes().hex())

verifier = Verifier(bitsize, 'BN254')
assert verifier.verify(proof, commitment)
print("Proof is valid!")
