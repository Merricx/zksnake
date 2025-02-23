import time
from zksnake.arithmetization import Var, ConstraintSystem
from zksnake.arithmetization.plonkish import Plonkish
from zksnake.constant import BN254_SCALAR_FIELD
from zksnake.plonk import Plonk


def run(n_power, crv):

    time_results = []

    v = []
    inp = Var("inp")
    out = Var("out")
    for i in range(n_power - 1):
        v.append(Var(f"v{i}"))

    cs = ConstraintSystem(["inp"], ["out"], BN254_SCALAR_FIELD)

    cs.add_constraint(v[0] == inp * inp)
    for i in range(1, n_power - 1):
        cs.add_constraint(v[i] == v[i - 1] * inp)

    cs.add_constraint(out == v[n_power - 2])
    cs.set_public(out)

    start = time.time()
    plonkish = Plonkish(cs, crv)
    plonkish.compile()
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    pub, priv = plonkish.generate_witness(cs.solve({"inp": 2, "out": 2**n_power}))
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    plonk = Plonk(plonkish, curve=crv)
    plonk.setup()
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    proof = plonk.prove(pub, priv)
    end = time.time() - start
    time_results.append(end)

    start = time.time()
    assert plonk.verify(proof, pub)
    end = time.time() - start
    time_results.append(end)

    return time_results


n_constraint = [2**10, 2**11, 2**12, 2**13, 2**14, 2**15, 2**16]
crvs = ["BN254"]

results = []
for n in n_constraint:
    for crv in crvs:
        result = run(n, crv)
        print(f"{n} constraints with {crv} curve")
        print("=" * 50)
        print("Compile time:", result[0])
        print("Witness gen time:", result[1])
        print("Setup time:", result[2])
        print("Prove time:", result[3])
        print("Verify time:", result[4])
        print()
