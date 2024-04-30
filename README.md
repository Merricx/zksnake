# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge).

## Security

<!-- prettier-ignore-start -->
> [!WARNING] 
**This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is NOT fully tested and NOT production-ready library!**
<!-- prettier-ignore-end -->

That being said, this library aims to be as correct as possible to standard practice in the real-world implementation. If you find vulnerability, incorrectness, or something to improve from this project, feel free to raise it via [Github Issues](https://github.com/Merricx/zksnake/issues) or privately.

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

We all know that Python is very slow and so this library. Therefore, to significantly improve the performance, it is recommended that you use one of these two options:

- Use flint backend (`pip install zksnake[flint]`)
- Use [`pypy`](https://www.pypy.org/) runtime to run the script

Flint backend will improve the R1CS compilation speed while pypy will improve overall performance in setup, proving, and verifying.

By default, zksnake will always use flint. If it is not installed (along with `python-flint`) then it will fallback to naive implementation.

### Benchmark

The benchmark was done in Macbook Pro M1.

#### Cpython + flint

```bash
$ python3 benchmarks/benchmark_script.py

64 constraints
==================================================
Compile time: 0.04321098327636719
Setup time: 2.715744972229004
Prove time: 2.3567428588867188
Verify time: 1.152388095855713

128 constraints
==================================================
Compile time: 0.22516584396362305
Setup time: 5.3968610763549805
Prove time: 4.7566611766815186
Verify time: 1.1188290119171143

256 constraints
==================================================
Compile time: 1.4860730171203613
Setup time: 10.739224910736084
Prove time: 9.844039916992188
Verify time: 1.1289052963256836

512 constraints
==================================================
Compile time: 10.893564939498901
Setup time: 21.713908910751343
Prove time: 20.50622296333313
Verify time: 1.1291019916534424

1024 constraints
==================================================
Compile time: 86.04900884628296
Setup time: 43.996793031692505
Prove time: 42.76715803146362
Verify time: 1.1460270881652832
```

#### pypy

```bash
$ pypy3 benchmarks/benchmark_script.py

64 constraints
==================================================
Compile time: 0.1528301239013672
Setup time: 1.1552870273590088
Prove time: 0.8961300849914551
Verify time: 0.4104440212249756

128 constraints
==================================================
Compile time: 0.6283810138702393
Setup time: 2.052640914916992
Prove time: 1.7928578853607178
Verify time: 0.3657200336456299

256 constraints
==================================================
Compile time: 3.1380980014801025
Setup time: 4.144614934921265
Prove time: 3.8131330013275146
Verify time: 0.36926913261413574

512 constraints
==================================================
Compile time: 20.172559022903442
Setup time: 8.932054042816162
Prove time: 7.920897006988525
Verify time: 0.44397997856140137

1024 constraints
==================================================
Compile time: 136.3906991481781
Setup time: 18.820957899093628
Prove time: 16.348512887954712
Verify time: 0.3562588691711426
```

_There is no significant difference when using **pypy+flint** due to the poor performance of pypy when using flint_
