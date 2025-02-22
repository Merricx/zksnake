# zksnake

Python implementation of zk-SNARKs (Zero Knowledge Succint Non-interactive ARgument of Knowledge) using simple symbolic expression.

<!-- prettier-ignore-start -->
> [!WARNING] 
**This library is intended to be used as proof of concept, prototyping, and educational purpose only. It is still unstable and not fully tested!**
<!-- prettier-ignore-end -->

## Proving schemes and curves

zksnake currently only supports [**Groth16**](https://eprint.iacr.org/2016/260.pdf) and [**PlonK**](https://eprint.iacr.org/2019/953.pdf) (original version) along with `BN254` and `BLS12-381` as supported curves. More proving schemes will be implemented in the future (hopefully).

## Usage

### Build constraints

```python
from zksnake.arithmetization import Var, ConstraintSystem, R1CS
from zksnake.constant import BN254_SCALAR_FIELD

x = Var('x')
y = Var('y')
v1 = Var('v1')

# prove the solution of y == x**3 + x + 5
# with x as input and y as output
cs = ConstraintSystem(['x'], ['y'], BN254_SCALAR_FIELD)
cs.add_constraint(v1 == x * x)
cs.add_constraint(y - 5 - x == v1 * x)
cs.set_public(y)

r1cs = R1CS(cs)
r1cs.compile()
```

Alternatively, you can import the constraints from [Circom](https://github.com/iden3/circom):

```python
from zksnake.arithmetization import R1CS

r1cs = R1CS.from_file("circuit.r1cs", "circuit.sym")
r1cs.compile()
```

Note that some constraints that are complex or expensive (require off-circuit computation) cannot be imported directly and require you to add "hint" function to pre-define the variable value (see [Example](./examples/example_bitify_circom.py)).

### Prove and verify proof

```python
from zksnake.groth16 import Groth16

# trusted setup
proof_system = Groth16(r1cs)
proof_system.setup()

# solve the constraint system
solution = r1cs.solve({'x': 3})
public_witness, private_witness = r1cs.generate_witness(solution)

# proving
proof = proof_system.prove(public_witness, private_witness)

# verification
assert proof_system.verify(proof, public_witness)
```

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
