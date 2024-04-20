# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge).

## Security

> [!WARNING] **This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is NOT production-ready library!**

That being said, this library aims to be as correct as possible to standard practice in the real-world implementation. If you find vulnerability or incorrectness from this project, feel free to report it privately or via [Github Issues](https://github.com/Merricx/zksnake/issues).

## Proving schemes and curves

zksnake currently only support **Groth16** proving scheme with `BN254` and `BLS12-381` as supported curves. More proving schemes will be implemented in the future (hopefully).

## Installation

Requirements: **Python >= 3.8**

```
pip install zksnake
```

Additionally, if you have [flint](https://flintlib.org/) installed, you can use the following command to make zksnake use flint backend (via `python-flint`) to significantly improve the performance of the Polynomial arithmetic operation.

```
pip install zksnake[flint]
```

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

public_witness, private_witness = cs.solve({'x': 3}, 35)

prover = Prover(qap, prover_key)
proof = prover.prove(public_witness, private_witness)

verifier = Verifier(verifier_key)
assert verifier.verify(proof, public_witness)
```
