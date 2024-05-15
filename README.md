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

| Constraints | Compile  | Setup    | Prove   | Verify  |
| ----------- | -------- | -------- | ------- | ------- |
| 256         | 0.0531s  | 0.4860s  | 0.2449s | 0.0020s |
| 512         | 0.1414s  | 0.3414s  | 0.2339s | 0.0019s |
| 1024        | 0.5691s  | 1.2426s  | 0.6390s | 0.0020s |
| 2048        | 2.4907s  | 4.6773s  | 2.1963s | 0.0019s |
| 4096        | 14.5036s | 19.5636s | 9.7119s | 0.0020s |

#### BLS12-381

| Constraints | Compile  | Setup    | Prove   | Verify  |
| ----------- | -------- | -------- | ------- | ------- |
| 256         | 0.03435s | 0.1421s  | 0.1282s | 0.0027s |
| 512         | 0.1436s  | 0.4677s  | 0.2763s | 0.0027s |
| 1024        | 0.6380s  | 1.3437s  | 0.7050s | 0.0027s |
| 2048        | 2.5698s  | 5.1675s  | 2.4186s | 0.0028s |
| 4096        | 15.1755s | 19.0513s | 8.8341s | 0.0030s |
