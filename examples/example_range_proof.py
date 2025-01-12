"""
Prove that v is in range of [0, 2^32-1] without revealing the value of v itself
using Inner Product Argument (Bulletproofs)
"""
from zksnake.subprotocol.bulletproofs import RangeProof

bitsize = 32
bulletproofs = RangeProof(bitsize, 'BN254')

# secret value v
value = 133337

proof = bulletproofs.prove(value)
print("Proof:", proof.to_bytes().hex())

assert bulletproofs.verify(proof)
print("Proof is valid!")
