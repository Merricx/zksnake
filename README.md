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

```bash
$ python3 benchmarks/benchmark_script.py

256 constraints
==================================================
Compile time: 0.03383898735046387
Setup time: 0.24071812629699707
Prove time: 0.10752201080322266
Verify time: 0.0019559860229492188

512 constraints
==================================================
Compile time: 0.14043331146240234
Setup time: 0.4345536231994629
Prove time: 0.23484110832214355
Verify time: 0.0019159317016601562

1024 constraints
==================================================
Compile time: 0.5702369213104248
Setup time: 1.2666420936584473
Prove time: 0.6734471321105957
Verify time: 0.001953125

2048 constraints
==================================================
Compile time: 2.5771420001983643
Setup time: 4.66642689704895
Prove time: 2.2481582164764404
Verify time: 0.0019867420196533203

4096 constraints
==================================================
Compile time: 12.395374059677124
Setup time: 17.877058029174805
Prove time: 7.910065174102783
Verify time: 0.0020728111267089844
```
