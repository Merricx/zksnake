import time
from zksnake.symbolic import Symbol
from zksnake.arithmetization.plonkish import ConstraintSystem

from zksnake.plonk import Setup, Prover, Verifier


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

    start = time.time()
    plonkish = cs.compile()
    end = time.time() - start
    time_results.append(end)

    pub, priv = cs.solve({"inp": 2}, {"out": 2**n_power})

    start = time.time()
    setup = Setup(plonkish, curve=crv)
    pk, vk = setup.generate()
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    prover = Prover(pk)
    proof = prover.prove(pub, priv)
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    verifier = Verifier(vk)
    assert verifier.verify(proof, pub)
    end = time.time() - start
    time_results.append(end)

    return time_results


n_constraint = [2**11, 2**12, 2**13, 2**14]
crvs = ["BN254"]

results = []
for n in n_constraint:
    for crv in crvs:
        result = run(n, crv)
        print(f"{n} constraints with {crv} curve")
        print("=" * 50)
        print("Compile time:", result[0])
        print("Setup time:", result[1])
        print("Prove time:", result[2])
        print("Verify time:", result[3])
        print()
