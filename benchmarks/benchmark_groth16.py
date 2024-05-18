import time
from zksnake.symbolic import Symbol
from zksnake.r1cs import ConstraintSystem

from zksnake.groth16 import Setup, Prover, Verifier


def run(n_power, crv):

    time_results = []

    v = []
    inp = Symbol("inp")
    out = Symbol("out")
    for i in range(n_power - 1):
        v.append(Symbol(f"v{i}"))

    cs = ConstraintSystem([inp], ["out"], crv)

    cs.add_constraint(v[0] == inp * inp)
    for i in range(1, n_power - 1):
        cs.add_constraint(v[i] == v[i - 1] * inp)

    cs.add_constraint(out == v[n_power - 2])
    cs.set_public(out)

    qap = cs.compile()

    start = time.time()
    pub, priv = cs.solve({"inp": 2}, {"out": 2**n_power})
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    setup = Setup(qap, crv)
    pk, vk = setup.generate()
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    prover = Prover(qap, pk, crv)
    proof = prover.prove(pub, priv)
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    verifier = Verifier(vk, crv)
    assert verifier.verify(proof, pub)
    end = time.time() - start
    time_results.append(end)

    return time_results


n_constraint = [2**10, 2**11, 2**12, 2**13, 2**14]
crvs = ["BN254", "BLS12_381"]

results = []
for n in n_constraint:
    for crv in crvs:
        result = run(n, crv)
        print(f"{n} constraints with {crv} curve")
        print("=" * 50)
        print("Solve time:", result[0])
        print("Setup time:", result[1])
        print("Prove time:", result[2])
        print("Verify time:", result[3])
        print()
