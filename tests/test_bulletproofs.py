import pytest
from zksnake.subprotocol.bulletproofs import RangeProof, InnerProductArgument, InnerProductProof
from zksnake.subprotocol.bulletproofs.range_proof import RangeProofObject


def test_ipa_bn254():

    a = [1,3,3,7]
    b = [1,2,3,4]
    
    ipa = InnerProductArgument(8, 'BN254')
    proof, comm = ipa.prove(a, b)

    proof = proof.to_bytes()

    assert ipa.verify(InnerProductProof.from_bytes(proof), comm)


def test_ipa_bls12_381():

    a = [1,3,3,7]
    b = [1,2,3,4]
    
    ipa = InnerProductArgument(8, 'BLS12_381')
    proof, comm = ipa.prove(a, b)

    proof = proof.to_bytes()

    assert ipa.verify(InnerProductProof.from_bytes(proof, 'BLS12_381'), comm)

def test_range_proof_bn254():
    
    rp = RangeProof(32, 'BN254')
    proof = rp.prove(1337)

    assert rp.verify(proof)

    rp = RangeProof(8, 'BN254')
    proof = rp.prove(500)

    assert not rp.verify(proof)

def test_range_proof_bls12_381():
    
    rp = RangeProof(32, 'BLS12_381')
    proof = rp.prove(1337)

    assert rp.verify(proof)

    rp = RangeProof(8, 'BLS12_381')
    proof = rp.prove(500)

    assert not rp.verify(proof)

def test_range_proof_serialization():

    rp = RangeProof(32, 'BN254')
    proof = rp.prove(1337)

    proof = proof.to_bytes()

    assert rp.verify(RangeProofObject.from_bytes(proof))

    rp = RangeProof(32, 'BLS12_381')
    proof = rp.prove(1337)

    proof = proof.to_bytes()

    assert rp.verify(RangeProofObject.from_bytes(proof, 'BLS12_381'))