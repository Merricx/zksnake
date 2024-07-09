"""
R1CS template of Poseidon hash

Heavily referenced from:
https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
"""

from ...symbolic import Symbol, SymbolArray
from ...r1cs import ConstraintTemplate
from .constants import poseidon_bn254


class Sigma(ConstraintTemplate):

    def main(self, *args):

        inp = args[0]
        out = args[1]

        inp2 = Symbol("inp2")
        inp4 = Symbol("inp4")

        self.add_constraint(inp2 == inp * inp)
        self.add_constraint(inp4 == inp2 * inp2)
        self.add_constraint(out == inp4 * inp)


class Ark(ConstraintTemplate):
    def __init__(self, t, C, r):
        super().__init__()
        self.t = t
        self.C = C
        self.r = r

    def main(self, *args):

        inp = args[0]
        out = args[1]

        for i in range(self.t):
            # TODO: This addition can be combined with Mix operation
            self.add_constraint(out[i] == inp[i] + self.C[i + self.r])


class Mix(ConstraintTemplate):
    def __init__(self, t, M):
        super().__init__()
        self.t = t
        self.M = M

    def main(self, *args):
        inp = args[0]
        out = args[1]

        for i in range(self.t):
            lc = 0
            for j in range(self.t):
                lc += self.M[j][i] * inp[j]

            self.add_constraint(out[i] == lc)


class MixLast(ConstraintTemplate):
    def __init__(self, t, M, s):
        super().__init__()
        self.t = t
        self.M = M
        self.s = s

    def main(self, *args):
        inp = args[0]
        out = args[1]

        lc = 0
        for j in range(self.t):
            lc += self.M[j][self.s] * inp[j]

        self.add_constraint(out == lc)


class MixS(ConstraintTemplate):
    def __init__(self, t, S, r):
        super().__init__()
        self.t = t
        self.S = S
        self.r = r

    def main(self, *args):

        inp = args[0]
        out = args[1]

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
        self.n_in = n_in
        self.n_out = n_out

    def main(self, *args):

        init_state = args[0]
        inp = args[1]
        out = args[2]

        N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
        t = self.n_in + 1
        n_rounds_f = 8
        n_rounds_p = N_ROUNDS_P[t - 2]

        # Note that Poseidon constants for BLS12-381 is not implemented yet
        C = poseidon_bn254.POSEIDON_C(t)
        S = poseidon_bn254.POSEIDON_S(t)
        M = poseidon_bn254.POSEIDON_M(t)
        P = poseidon_bn254.POSEIDON_P(t)

        ################################################################################
        # ADD PRE-ROUND CONSTANT
        ################################################################################

        ark_out = []
        for i in range(n_rounds_p):
            ark_out.append(SymbolArray(f"ark.out[{i}]", t))

        ark = Ark(t, C, 0)
        ark_input = SymbolArray("ark.in[0]", t)
        for j in range(t):
            if j > 0:
                ark_input[j] = inp[j - 1]
            else:
                ark_input[j] = init_state

        self.add_template(ark_out[0] == ark("ark[0]", ark_input))

        mix_out = []
        for i in range(n_rounds_f - 1):
            mix_out.append(SymbolArray(f"mix.out[{i}]", t))

        sigmaF_out = []
        for i in range(n_rounds_f):
            sigmaF_out.append([])
            for j in range(t):
                sigmaF_out[i].append(Symbol(f"sigmaF.out[{i}][{j}]"))

        ################################################################################
        # FIRST HALF FULL ROUNDS
        ################################################################################

        sigmaF = Sigma()
        for r in range(n_rounds_f // 2 - 1):
            for j in range(t):
                if r == 0:
                    self.add_template(
                        sigmaF_out[r][j] == sigmaF(f"sigmaF[{r}][{j}]", ark_out[0][j])
                    )
                else:
                    self.add_template(
                        sigmaF_out[r][j]
                        == sigmaF(f"sigmaF[{r}][{j}]", mix_out[r - 1][j])
                    )

            ark = Ark(t, C, (r + 1) * t)
            self.add_template(ark_out[r + 1] == ark(f"ark[{r+1}]", sigmaF_out[r]))

            mix = Mix(t, M)
            self.add_template(mix_out[r] == mix(f"mix[{r}]", ark_out[r + 1]))

        for j in range(t):
            self.add_template(
                sigmaF_out[n_rounds_f // 2 - 1][j]
                == sigmaF(
                    f"sigmaF[{n_rounds_f//2-1}][{j}]", mix_out[n_rounds_f // 2 - 2][j]
                )
            )

        ark = Ark(t, C, (n_rounds_f // 2) * t)
        self.add_template(
            ark_out[n_rounds_f // 2]
            == ark(f"ark[{n_rounds_f//2}]", sigmaF_out[n_rounds_f // 2 - 1])
        )

        mix = Mix(t, P)
        self.add_template(
            mix_out[n_rounds_f // 2 - 1]
            == mix(f"mix[{n_rounds_f//2-1}]", ark_out[n_rounds_f // 2])
        )

        ################################################################################
        # MIDDLE PARTIAL ROUNDS
        ################################################################################

        sigmaP_out = SymbolArray("sigmaP.out", n_rounds_p)

        mixS_out = []
        for i in range(n_rounds_p):
            mixS_out.append(SymbolArray(f"mixS.out[{i}]", t))

        sigmaP = Sigma()

        for r in range(n_rounds_p):
            if r == 0:
                self.add_template(
                    sigmaP_out[r]
                    == sigmaP(f"sigmaP[{r}]", mix_out[n_rounds_f // 2 - 1][0])
                )
            else:
                self.add_template(
                    sigmaP_out[r]
                    == sigmaP(
                        f"sigmaP[{r}]",
                        mixS_out[r - 1][0],
                    )
                )

            mixS = MixS(t, S, r)
            mixS_input = SymbolArray("mixS.in", t)
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

                    mixS_input[j] = sigmaP_out_aux
                else:
                    if r == 0:
                        mixS_input[j] = mix_out[n_rounds_f // 2 - 1][j]
                    else:
                        mixS_input[j] = mixS_out[r - 1][j]

            self.add_template(mixS_out[r] == mixS(f"mixS[{r}]", mixS_input))

        ################################################################################
        # SECOND FULL HALF ROUNDS
        ################################################################################

        for r in range(n_rounds_f // 2 - 1):

            for j in range(t):
                if r == 0:
                    self.add_template(
                        sigmaF_out[n_rounds_f // 2 + r][j]
                        == sigmaF(
                            f"sigmaF[{n_rounds_f//2+r}][{j}]",
                            mixS_out[n_rounds_p - 1][j],
                        )
                    )
                else:
                    self.add_template(
                        sigmaF_out[n_rounds_f // 2 + r][j]
                        == sigmaF(
                            f"sigmaF[{n_rounds_f//2+r}][{j}]",
                            mix_out[n_rounds_f // 2 + r - 1][j],
                        )
                    )

            ark = Ark(t, C, (n_rounds_f // 2 + 1) * t + n_rounds_p + r * t)

            self.add_template(
                ark_out[n_rounds_f // 2 + r + 1]
                == ark(
                    f"ark[{n_rounds_f // 2 + r + 1}]",
                    sigmaF_out[n_rounds_f // 2 + r],
                )
            )

            mix = Mix(t, M)

            self.add_template(
                mix_out[n_rounds_f // 2 + r]
                == mix(f"mix[{n_rounds_f // 2 + r}]", ark_out[n_rounds_f // 2 + r + 1])
            )

        ################################################################################
        # LAST ROUND
        ################################################################################

        for j in range(t):
            self.add_template(
                sigmaF_out[n_rounds_f - 1][j]
                == sigmaF(
                    f"sigmaF[{n_rounds_f-1}][{j}]",
                    mix_out[n_rounds_f - 2][j],
                )
            )

        for i in range(self.n_out):
            mix_last = MixLast(t, M, i)

            self.add_template(
                out[i] == mix_last(f"mixLast[{i}]", sigmaF_out[n_rounds_f - 1])
            )


class Poseidon(ConstraintTemplate):
    def __init__(self, n):
        super().__init__()
        self.n_input = n

        assert n < 17

    def main(self, *args):

        inp = args[0]
        out = args[1]

        init_state = Symbol("init_state")

        assert isinstance(inp, SymbolArray) and len(inp) == self.n_input
        assert isinstance(out, SymbolArray) and len(out) == 1

        self.add_hint(lambda: 0, init_state, args=())

        pEx = PoseidonEx(self.n_input, 1)

        self.add_template(out == pEx("pEx", init_state, inp))
