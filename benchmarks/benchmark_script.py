import time
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem

from zksnake.groth16 import Setup, Prover, Verifier


def run(n_power):

    time_results = []

    v = []
    inp = Symbol("inp")
    out = Symbol("out")
    for i in range(n_power - 1):
        v.append(Symbol(f"v{i}"))

    cs = ConstraintSystem([inp], ["out"])

    cs.add(v[0] == inp * inp)
    for i in range(1, n_power - 1):
        cs.add(v[i] == v[i - 1] * inp)

    cs.add(out == v[n_power - 2])
    cs.set_public(out)

    start = time.time()
    qap = cs.compile()
    end = time.time() - start
    time_results.append(end)

    pub, priv = cs.solve({"inp": 2}, {"out": 2**n_power})

    start = time.time()
    setup = Setup(qap)
    pk, vk = setup.generate()
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    prover = Prover(qap, pk)
    proof = prover.prove(pub, priv)
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    verifier = Verifier(vk)
    assert verifier.verify(proof, pub)
    end = time.time() - start
    time_results.append(end)

    return time_results


n_constraint = [256, 512, 1024, 2048, 4096]

results = []
for i in n_constraint:
    results.append(run(i))


for i, result in enumerate(results):
    print(f"{n_constraint[i]} constraints")
    print("=" * 50)
    print("Compile time:", result[0])
    print("Setup time:", result[1])
    print("Prove time:", result[2])
    print("Verify time:", result[3])
    print()
