# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge).

## Security

<!-- prettier-ignore-start -->
> [!WARNING] 
**This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is NOT fully tested and NOT production-ready library!**
<!-- prettier-ignore-end -->

That being said, this library aims to be as correct as possible to standard practice in the real-world implementation. If you find security vulnerability, incorrectness, or something to improve from this project, feel free to raise it via [Github Issues](https://github.com/Merricx/zksnake/issues) or privately.

## Proving schemes and curves

zksnake currently only support **Groth16** proving scheme with `BN254` and `BLS12-381` as supported curves. More proving schemes will be implemented in the future (hopefully).

## Installation

Requirements: **Python >= 3.9**

```
pip install zksnake
```

Optionally, you can use the following command to make zksnake use [FLINT](https://flintlib.org/) backend (via `python-flint`) to significantly improve the performance (see [Performance](#performance)).

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
from zksnake.groth16 import Setup

setup = Setup(qap)

prover_key, verifier_key = setup.generate()
```

### Prove and verify proof

```python
from zksnake.groth16 import Prover, Verifier

public_witness, private_witness = cs.solve({'x': 3}, 35)

prover = Prover(qap, prover_key)
proof = prover.prove(public_witness, private_witness)

verifier = Verifier(verifier_key)
assert verifier.verify(proof, public_witness)
```

## Performance

We all know that Python is very slow and so this library. So, it cannot handle big constraints really well (above 10K constraints). Nevertheless, this library tries its best to achieve high performance by utilizing parallel computation, recomputation caching, and using [FLINT](https://flintlib.org/) as a backend for Polynomial arithmetic operation. 

Note that currently, running zksnake via pypy is slightly slower than Cpython.

### Benchmark

The benchmark was done in Macbook M1 Pro (10 cores @ 3.2 GHz).

```bash
$ python3 benchmarks/benchmark_script.py

128 constraints
==================================================
Compile time: 0.4393479824066162
Setup time: 1.9054968357086182
Prove time: 1.0913739204406738
Verify time: 0.3241112232208252

256 constraints
==================================================
Compile time: 0.40540003776550293
Setup time: 2.68823504447937
Prove time: 2.3178298473358154
Verify time: 0.3243279457092285

512 constraints
==================================================
Compile time: 1.0385169982910156
Setup time: 5.441917896270752
Prove time: 5.0203351974487305
Verify time: 0.4261047840118408

1024 constraints
==================================================
Compile time: 4.324009895324707
Setup time: 11.5020751953125
Prove time: 10.160172939300537
Verify time: 0.333420991897583

2048 constraints
==================================================
Compile time: 15.53832483291626
Setup time: 26.138340711593628
Prove time: 21.955264806747437
Verify time: 0.3329911231994629
```
