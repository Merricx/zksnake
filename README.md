# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge).

<!-- prettier-ignore-start -->
> [!WARNING] 
**This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is NOT fully tested and NOT production-ready library!**
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

Note that some constraints that are quite complex or expensive cannot just be imported directly and require you to add "hint" function to pre-define the variable value (see [Example](./examples/example_bitify_circom.py)).

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

Nevertheless, this library tries its best to achieve high performance as possible by utilizing Rust bindings via [pyo3](https://github.com/PyO3/pyo3) as a backend for all primitives computation based from [arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) libraries. It also uses parallel and caching in the Python code where it possible.

Note that running zksnake via pypy is slightly slower than Cpython.

### Benchmark

The benchmark was done in Macbook M1 Pro (8 cores).

#### BN254

| Constraints | Witness gen. | Setup    | Prove    | Verify  |
| ----------- | ------------ | -------- | -------- | ------- |
| 1024        | 0.0032s      | 0.6340s  | 0.4294s  | 0.0020s |
| 2048        | 0.0080s      | 0.8221s  | 1.1834s  | 0.0022s |
| 4096        | 0.0160s      | 2.9196s  | 2.7912s  | 0.0019s |
| 8192        | 0.0323s      | 11.0706s | 8.5577s  | 0.0021s |
| 16384       | 0.0683s      | 53.4517s | 49.3796s | 0.0021s |

#### BLS12-381

| Constraints | Witness gen. | Setup    | Prove    | Verify  |
| ----------- | ------------ | -------- | -------- | ------- |
| 1024        | 0.0040s      | 0.3635s  | 0.5530s  | 0.0028s |
| 2048        | 0.0081s      | 1.0009s  | 1.2754s  | 0.0028s |
| 4096        | 0.0159s      | 3.1688s  | 2.9886s  | 0.0029s |
| 8192        | 0.0327s      | 11.4986s | 8.8297s  | 0.0038s |
| 16384       | 0.0741s      | 49.5891s | 50.4789s | 0.0030s |
