# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge) using simple Symbolic expression.

<!-- prettier-ignore-start -->
> [!WARNING] 
**This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is still in active development and not fully tested!**
<!-- prettier-ignore-end -->

## Proving schemes and curves

zksnake currently only support **Groth16** proving scheme with `BN254` and `BLS12-381` as supported curves. More proving schemes will be implemented in the future (hopefully).

## Usage

### Build constraints into QAP

```python
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem

x = Symbol('x')
y = Symbol('y')
v1 = Symbol('v1')

# prove the solution of y == x**3 + x + 5
# where x as input and y as output
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

Note that some constraints that are complex or expensive (require off-circuit computation) cannot be imported directly and require you to add "hint" function to pre-define the variable value (see [Example](./examples/example_bitify_circom.py)).

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

| Constraints | Compile | Setup   | Prove   | Verify  |
| ----------- | ------- | ------- | ------- | ------- |
| 1024        | 0.0154s | 0.7227s | 0.1201s | 0.0022s |
| 2048        | 0.0414s | 0.3480s | 0.2009s | 0.0019s |
| 4096        | 0.1341s | 0.5656s | 0.3827s | 0.0030s |
| 8192        | 0.5653s | 1.1019s | 0.7292s | 0.0019s |
| 16384       | 0.9669s | 2.5485s | 1.3710s | 0.0020s |
| 32768       | 2.8420s | 4.9742s | 2.6942s | 0.0020s |
| 65536       | 9.9637s | 8.8074s | 4.8914s | 0.0021s |

## Development

Requirements:

- python3 >= 3.9
- rust >= 1.77

Install maturin:

```
pip install maturin
```

Setup virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate
```

Compile and install the editable module into venv:

```
maturin develop -r -E dev
```

Test the script:

```
python3 -m pytest tests
```
