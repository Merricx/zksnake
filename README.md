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
pip install zksnake[flint]
```

It is recommended to use `[flint]` to make zksnake use [FLINT](https://flintlib.org/) backend (via `python-flint`) to significantly improve the performance (see [Performance](#performance)).

If somehow the FLINT installation fails, you can use the following command to fallback to naive implementation (significantly slower):

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
cs = ConstraintSystem(['x'], 'y')
cs.add(v1 == x*x)
cs.add(y - 5 - x == v1*x)
cs.set_public(y)

qap = cs.compile()
```

### Trusted setup phase

```python
from zksnake.groth16 import Setup

setup = Setup(qap)

prover_key, verifier_key = setup.generate()
```

### Prove and verify proof

```python
from zksnake.groth16 import Prover, Verifier

# solve the constraint system
public_witness, private_witness = cs.solve({'x': 3}, 35)

# proving
prover = Prover(qap, prover_key)
proof = prover.prove(public_witness, private_witness)

# verification
verifier = Verifier(verifier_key)
assert verifier.verify(proof, public_witness)
```

## Performance

We all know that Python is very slow and so this library. So, it cannot handle big constraints really well (above 10K constraints). Nevertheless, this library tries its best to achieve high performance by utilizing parallel computation, recomputation caching, and using [FLINT](https://flintlib.org/) as a backend for Polynomial arithmetic operation.

Note that currently, running zksnake via pypy is slightly slower than Cpython.

### Benchmark

The benchmark was done in Macbook M1 Pro (8 cores).

```bash
$ python3 benchmarks/benchmark_script.py

256 constraints
==================================================
Compile time: 0.6396217346191406
Setup time: 3.0364649295806885
Prove time: 2.202207088470459
Verify time: 0.3272390365600586

512 constraints
==================================================
Compile time: 0.8920221328735352
Setup time: 4.902499198913574
Prove time: 4.415348052978516
Verify time: 0.3332400321960449

1024 constraints
==================================================
Compile time: 3.3228960037231445
Setup time: 10.271549224853516
Prove time: 9.695584058761597
Verify time: 0.33088111877441406

2048 constraints
==================================================
Compile time: 10.464536190032959
Setup time: 24.079060077667236
Prove time: 21.201593160629272
Verify time: 0.33314990997314453

4096 constraints
==================================================
Compile time: 44.15011692047119
Setup time: 63.6544508934021
Prove time: 50.83850812911987
Verify time: 0.3527970314025879
```
