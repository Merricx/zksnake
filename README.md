# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge).

<!-- prettier-ignore-start -->
> [!WARNING] 
**This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is NOT fully tested and NOT formally verified!**
<!-- prettier-ignore-end -->

## Proving schemes and curves

zksnake currently only support **Groth16** proving scheme with `BN254` and `BLS12-381` as supported curves. More proving schemes will be implemented in the future (hopefully).

## Installation

Requirements: **Python >= 3.9**

```
pip install zksnake
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
# x as input and y as output
cs = ConstraintSystem(['x'], ['y'])
cs.add_constraint(v1 == x*x)
cs.add_constraint(y - 5 - x == v1*x)
cs.set_public(y)

qap = cs.compile()
```

Alternatively, you can import the constraints from [Circom](https://github.com/iden3/circom):

```python
from zksnake.r1cs import ConstraintSystem

cs = ConstraintSystem.from_file("circuit.r1cs", "circuit.sym")
qap = cs.compile()
```

Note that some constraints that are complex or expensive cannot just be imported directly and require you to add "hint" function to pre-define the variable value (see [Example](./examples/example_bitify_circom.py)).

### Trusted setup phase

```python
from zksnake.groth16 import Setup

# one time setup
setup = Setup(qap)
prover_key, verifier_key = setup.generate()
```

### Prove and verify proof

```python
from zksnake.groth16 import Prover, Verifier

# solve the constraint system
public_witness, private_witness = cs.solve({'x': 3}, {'y': 35})

# proving
prover = Prover(qap, prover_key)
proof = prover.prove(public_witness, private_witness)

# verification
verifier = Verifier(verifier_key)
assert verifier.verify(proof, public_witness)
```

## Performance

It is difficult to achieve high performance due to the nature of Python and there are still many unoptimized code (ie. using naive implementation) in the current implementation.

Nevertheless, this library tries its best to achieve high performance as possible by utilizing Rust bindings via [pyo3](https://github.com/PyO3/pyo3) as a backend for all primitives computation based from [arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) libraries.

Note that running zksnake via pypy is slightly slower than Cpython.

### Benchmark

The benchmark was done in Macbook M1 Pro (8 cores).

| Constraints | Compile   | Setup   | Prove   | Verify  |
| ----------- | --------- | ------- | ------- | ------- |
| 1024        | 0.1851s   | 0.4726s | 0.1446s | 0.0022s |
| 2048        | 0.5245s   | 0.7532s | 0.2887s | 0.0030s |
| 4096        | 1.8482s   | 1.1695s | 0.7613s | 0.0019s |
| 8192        | 5.1625s   | 0.8948s | 0.0183s | 0.0017s |
| 16384       | 27.0381s  | 1.9134s | 0.0376s | 0.0017s |
| 32768       | 111.4407s | 3.7884s | 0.0738s | 0.0017s |

_Performance is currently sacrificed in compile time due to transformation from dense array to sparse array in order to gain faster setup and proving time_
