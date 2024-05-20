from ..symbolic import Symbol
from ..r1cs import ConstraintTemplate
from .constants.poseidon import POSEIDON_C, POSEIDON_M, POSEIDON_P, POSEIDON_S


class Sigma(ConstraintTemplate):
    def __init__(self):
        super().__init__()
        self.inputs = ["inp"]
        self.outputs = ["out"]

    def main(self):

        inp = Symbol("inp")
        out = Symbol("out")

        inp2 = Symbol("inp2")
        inp4 = Symbol("inp4")

        self.add_constraint(inp2 == inp * inp)
        self.add_constraint(inp4 == inp2 * inp2)
        self.add_constraint(out == inp4 * inp)


class Ark(ConstraintTemplate):
    def __init__(self, t, C, r):
        super().__init__()
        self.inputs = [f"inp{i}" for i in range(t)]
        self.outputs = [f"out{i}" for i in range(t)]
        self.t = t
        self.C = C
        self.r = r

    def main(self):

        inp = [Symbol(f"inp{i}") for i in range(self.t)]
        out = [Symbol(f"out{i}") for i in range(self.t)]

        for i in range(self.t):
            # TODO: This addition can be combined with Mix operation
            self.add_constraint(out[i] == inp[i] + self.C[i + self.r])


class Mix(ConstraintTemplate):
    def __init__(self, t, M):
        super().__init__()
        self.inputs = [f"inp{i}" for i in range(t)]
        self.outputs = [f"out{i}" for i in range(t)]
        self.t = t
        self.M = M

    def main(self):
        inp = [Symbol(f"inp{i}") for i in range(self.t)]
        out = [Symbol(f"out{i}") for i in range(self.t)]

        for i in range(self.t):
            lc = 0
            for j in range(self.t):
                lc += self.M[j][i] * inp[j]

            self.add_constraint(out[i] == lc)


class MixLast(ConstraintTemplate):
    def __init__(self, t, M, s):
        super().__init__()
        self.inputs = [f"inp{i}" for i in range(t)]
        self.outputs = ["out"]
        self.t = t
        self.M = M
        self.s = s

    def main(self):
        inp = [Symbol(f"inp{i}") for i in range(self.t)]
        out = Symbol("out")

        lc = 0
        for j in range(self.t):
            lc += self.M[j][self.s] * inp[j]

        self.add_constraint(out == lc)


class MixS(ConstraintTemplate):
    def __init__(self, t, S, r):
        super().__init__()
        self.inputs = [f"inp{i}" for i in range(t)]
        self.outputs = [f"out{i}" for i in range(t)]
        self.t = t
        self.S = S
        self.r = r

    def main(self):

        inp = [Symbol(f"inp{i}") for i in range(self.t)]
        out = [Symbol(f"out{i}") for i in range(self.t)]

        lc = 0
        for i in range(self.t):
            lc += self.S[(self.t * 2 - 1) * self.r + i] * inp[i]

        self.add_constraint(out[0] == lc)
        for i in range(1, self.t):
            self.add_constraint(
                out[i]
                == inp[i] + inp[0] * self.S[(self.t * 2 - 1) * self.r + self.t + i - 1]
            )


class PoseidonEx(ConstraintTemplate):
    def __init__(self, n_in, n_out):
        super().__init__()
        self.inputs = [f"inp{i}" for i in range(n_in)] + ["init_state"]
        self.outputs = [f"out{i}" for i in range(n_out)]
        self.n_in = n_in
        self.n_out = n_out

    def main(self):

        init_state = Symbol("init_state")
        inp = [Symbol(f"inp{i}") for i in range(self.n_in)]
        out = [Symbol(f"out{i}") for i in range(self.n_out)]

        N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
        t = self.n_in + 1
        n_rounds_f = 8
        n_rounds_p = N_ROUNDS_P[t - 2]

        C = POSEIDON_C(t)
        S = POSEIDON_S(t)
        M = POSEIDON_M(t)
        P = POSEIDON_P(t)

        ################################################################################
        #
        ################################################################################

        ark_out = []
        for i in range(n_rounds_p):
            ark_out.append([Symbol(f"ark.out[{i}][{j}]") for j in range(t)])

        ark = Ark(t, C, 0)
        ark_input = {}
        ark_output = {}
        for j in range(t):
            ark_output[f"out{j}"] = ark_out[0][j]
            if j > 0:
                ark_input[f"inp{j}"] = inp[j - 1]
            else:
                ark_input[f"inp{j}"] = init_state

        self.add_template(ark("ark[0]", ark_input, ark_output))

        mix_out = []
        for i in range(n_rounds_f - 1):
            mix_out.append([Symbol(f"mix.out[{i}][{j}]") for j in range(t)])

        sigmaF_out = []
        for i in range(n_rounds_f):
            sigmaF_out.append([])
            for j in range(t):
                sigmaF_out[i].append(Symbol(f"sigmaF.out[{i}][{j}]"))

        ################################################################################
        #
        ################################################################################

        sigmaF = Sigma()
        for r in range(n_rounds_f // 2 - 1):
            for j in range(t):
                if r == 0:
                    self.add_template(
                        sigmaF(
                            f"sigmaF[{r}][{j}]",
                            {"inp": ark_out[0][j]},
                            {"out": sigmaF_out[r][j]},
                        )
                    )
                else:
                    self.add_template(
                        sigmaF(
                            f"sigmaF[{r}][{j}]",
                            {"inp": mix_out[r - 1][j]},
                            {"out": sigmaF_out[r][j]},
                        )
                    )

            ark = Ark(t, C, (r + 1) * t)
            ark_input = {}
            ark_output = {}
            for j in range(t):
                ark_output[f"out{j}"] = ark_out[r + 1][j]
                ark_input[f"inp{j}"] = sigmaF_out[r][j]

            self.add_template(ark(f"ark[{r+1}]", ark_input, ark_output))

            mix = Mix(t, M)
            mix_input = {}
            mix_output = {}
            for j in range(t):
                mix_output[f"out{j}"] = mix_out[r][j]
                mix_input[f"inp{j}"] = ark_out[r + 1][j]

            self.add_template(mix(f"mix[{r}]", mix_input, mix_output))

        for j in range(t):
            self.add_template(
                sigmaF(
                    f"sigmaF[{n_rounds_f//2-1}][{j}]",
                    {"inp": mix_out[n_rounds_f // 2 - 2][j]},
                    {"out": sigmaF_out[n_rounds_f // 2 - 1][j]},
                )
            )

        ark = Ark(t, C, (n_rounds_f // 2) * t)
        ark_input = {}
        ark_output = {}
        for j in range(t):
            ark_output[f"out{j}"] = ark_out[n_rounds_f // 2][j]
            ark_input[f"inp{j}"] = sigmaF_out[n_rounds_f // 2 - 1][j]

        self.add_template(ark(f"ark[{n_rounds_f//2}]", ark_input, ark_output))

        mix = Mix(t, P)
        mix_input = {}
        mix_output = {}
        for j in range(t):
            mix_output[f"out{j}"] = mix_out[n_rounds_f // 2 - 1][j]
            mix_input[f"inp{j}"] = ark_out[n_rounds_f // 2][j]

        self.add_template(mix(f"mix[{n_rounds_f//2-1}]", mix_input, mix_output))

        ################################################################################
        #
        ################################################################################

        sigmaP_out = []
        for i in range(n_rounds_p):
            sigmaP_out.append(Symbol(f"sigmaP.out[{i}]"))

        mixS_out = []
        for i in range(n_rounds_p):
            mixS_out.append([Symbol(f"mixS.out[{i}][{j}]") for j in range(t)])

        sigmaP = Sigma()

        for r in range(n_rounds_p):
            if r == 0:
                self.add_template(
                    sigmaP(
                        f"sigmaP[{r}]",
                        {"inp": mix_out[n_rounds_f // 2 - 1][0]},
                        {"out": sigmaP_out[r]},
                    )
                )
            else:
                self.add_template(
                    sigmaP(
                        f"sigmaP[{r}]",
                        {"inp": mixS_out[r - 1][0]},
                        {"out": sigmaP_out[r]},
                    )
                )

            mixS = MixS(t, S, r)
            mixS_input = {}
            mixS_output = {}

            for j in range(t):
                mixS_output[f"out{j}"] = mixS_out[r][j]
                if j == 0:
                    # TODO: can be optimized by combining this constraint into MixS
                    sigmaP_out_aux = Symbol(f"sigmaP.out.aux[{r}]")
                    self.add_constraint(
                        sigmaP_out_aux
                        == sigmaP_out[r] + C[(n_rounds_f // 2 + 1) * t + r]
                    )

                    mixS_input[f"inp{j}"] = sigmaP_out_aux
                else:
                    if r == 0:
                        mixS_input[f"inp{j}"] = mix_out[n_rounds_f // 2 - 1][j]
                    else:
                        mixS_input[f"inp{j}"] = mixS_out[r - 1][j]

            self.add_template(mixS(f"mixS[{r}]", mixS_input, mixS_output))

        ################################################################################
        #
        ################################################################################

        for r in range(n_rounds_f // 2 - 1):

            for j in range(t):
                if r == 0:
                    self.add_template(
                        sigmaF(
                            f"sigmaF[{n_rounds_f//2+r}][{j}]",
                            {"inp": mixS_out[n_rounds_p - 1][j]},
                            {"out": sigmaF_out[n_rounds_f // 2 + r][j]},
                        )
                    )
                else:
                    self.add_template(
                        sigmaF(
                            f"sigmaF[{n_rounds_f//2+r}][{j}]",
                            {"inp": mix_out[n_rounds_f // 2 + r - 1][j]},
                            {"out": sigmaF_out[n_rounds_f // 2 + r][j]},
                        )
                    )

            ark = Ark(t, C, (n_rounds_f // 2 + 1) * t + n_rounds_p + r * t)
            ark_input = {}
            ark_output = {}
            for j in range(t):
                ark_output[f"out{j}"] = ark_out[n_rounds_f // 2 + r + 1][j]
                ark_input[f"inp{j}"] = sigmaF_out[n_rounds_f // 2 + r][j]

            self.add_template(
                ark(f"ark[{n_rounds_f // 2 + r + 1}]", ark_input, ark_output)
            )

            mix = Mix(t, M)
            mix_input = {}
            mix_output = {}
            for j in range(t):
                mix_output[f"out{j}"] = mix_out[n_rounds_f // 2 + r][j]
                mix_input[f"inp{j}"] = ark_out[n_rounds_f // 2 + r + 1][j]

            self.add_template(mix(f"mix[{n_rounds_f // 2 + r}]", mix_input, mix_output))

        ################################################################################
        #
        ################################################################################

        for j in range(t):
            self.add_template(
                sigmaF(
                    f"sigmaF[{n_rounds_f-1}][{j}]",
                    {"inp": mix_out[n_rounds_f - 2][j]},
                    {"out": sigmaF_out[n_rounds_f - 1][j]},
                )
            )

        for i in range(self.n_out):
            mix_last = MixLast(t, M, i)
            mix_last_input = {}
            for j in range(t):
                mix_last_input[f"inp{j}"] = sigmaF_out[n_rounds_f - 1][j]

            self.add_template(
                mix_last(f"mixLast[{i}]", mix_last_input, {"out": out[i]})
            )


class Poseidon(ConstraintTemplate):
    def __init__(self, n):
        super().__init__()
        self.inputs = [f"inp{i}" for i in range(n)]
        self.outputs = ["out"]
        self.n_input = n

        assert n < 17

    def main(self):

        inp = [Symbol(f"inp{i}") for i in range(self.n_input)]
        out = Symbol("out")
        init_state = Symbol("init_state")

        self.add_hint(lambda: 0, init_state, args=())

        pEx_input = {"init_state": init_state}
        for i in range(self.n_input):
            pEx_input[f"inp{i}"] = inp[i]

        pEx = PoseidonEx(self.n_input, 1)

        self.add_template(pEx("pEx", pEx_input, {"out0": out}))
