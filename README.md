# zksnake

Python implementation of zk-SNARKs

## Installation

```
pip3 install zksnake
```

## Proving schemes and curves

zksnake currently support the following zk-SNARKs:

- Groth16
- ???

with the following curves:

- BN254
- BLS12-381

## Usage

### Build your constraints into QAP

```python
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem

x = Symbol('x')
y = Symbol('y')
v1 = Symbol('v1')

# solution to: y == x**3 + x + 5
cs = ConstraintSystem(['x'], 'y')
cs.add(v1 == x*x)
cs.add(y - 5 - x == v1*x)
cs.set_public(y)

qap = cs.compile()
```

### Trusted setup phase

```python
from zksnake.groth16.setup import Setup

setup = Setup(qap)

prover_key, verifier_key = setup.generate()
```

### Prove and verify proof

```python
from zksnake.groth16.prover import Prover
from zksnake.groth16.verifier import Verifier

witness = cs.solve({'x': 3}, 35)
public_witness, private_witness = witness[:2], witness[2:]

prover = Prover(qap, prover_key)
proof = prover.prove(private_witness, public_witness)

verifier = Verifier(verifier_key)
assert verifier.verify(proof, public_witness)
```
