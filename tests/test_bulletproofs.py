import pytest
from zksnake.bulletproofs import ipa, range_proof


def test_ipa_bn254():

    a = [1,3,3,7]
    b = [1,2,3,4]
    
    prover = ipa.Prover(8, 'BN254')
    proof, comm = prover.prove(a, b)

    proof = proof.to_bytes()

    verifier = ipa.Verifier(8, 'BN254')
    assert verifier.verify(ipa.InnerProductProof.from_bytes(proof), comm)


def test_ipa_bls12_381():

    a = [1,3,3,7]
    b = [1,2,3,4]
    
    prover = ipa.Prover(8, 'BLS12_381')
    proof, comm = prover.prove(a, b)

    proof = proof.to_bytes()

    verifier = ipa.Verifier(8, 'BLS12_381')
    assert verifier.verify(ipa.InnerProductProof.from_bytes(proof, 'BLS12_381'), comm)

def test_range_proof_bn254():
    
    prover = range_proof.Prover(32, 'BN254')
    proof, comm = prover.prove(1337)

    verifier = range_proof.Verifier(32, 'BN254')
    assert verifier.verify(proof, comm)

    prover = range_proof.Prover(8, 'BN254')
    proof, comm = prover.prove(500)

    verifier = range_proof.Verifier(8, 'BN254')
    assert not verifier.verify(proof, comm)

def test_range_proof_bls12_381():
    
    prover = range_proof.Prover(32, 'BLS12_381')
    proof, comm = prover.prove(1337)

    verifier = range_proof.Verifier(32, 'BLS12_381')
    assert verifier.verify(proof, comm)

    prover = range_proof.Prover(8, 'BLS12_381')
    proof, comm = prover.prove(500)

    verifier = range_proof.Verifier(8, 'BLS12_381')
    assert not verifier.verify(proof, comm)

def test_range_proof_serialization():

    prover = range_proof.Prover(32, 'BN254')
    proof, comm = prover.prove(1337)

    proof = proof.to_bytes()

    verifier = range_proof.Verifier(32, 'BN254')
    assert verifier.verify(range_proof.RangeProof.from_bytes(proof), comm)

    prover = range_proof.Prover(32, 'BLS12_381')
    proof, comm = prover.prove(1337)

    proof = proof.to_bytes()

    verifier = range_proof.Verifier(32, 'BLS12_381')
    assert verifier.verify(range_proof.RangeProof.from_bytes(proof, 'BLS12_381'), comm)