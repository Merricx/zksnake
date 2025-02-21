"""
Prove that v is in range of [0, 2^32-1] without revealing the value of v itself
using Inner Product Argument (Bulletproofs)
"""

from zksnake.subprotocol.bulletproofs import RangeProof

bitsize = 32
bulletproofs = RangeProof(bitsize, "BN254")

# secret value v
value = 133337

proof = bulletproofs.prove(value)
assert bulletproofs.verify(proof)
print(f"Proof is valid: {value} is in valid 32-bit range")

# invalid secret value v
value = 2**32 + 1337

proof = bulletproofs.prove(value)
assert not bulletproofs.verify(proof)
print(f"Proof is invalid: {value} is not in valid 32-bit range")
