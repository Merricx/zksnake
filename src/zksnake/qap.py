from .polynomial import (
    PolynomialRing,
    lagrange_polynomial,
    vanishing_polynomial,
    clear_cache,
)

interpolation_cache = {}


class QAP:

    def __init__(self, p):
        self.U = []
        self.V = []
        self.W = []
        self.T = PolynomialRing([0], p)
        self.n_public = 0

        self.p = p

    def _r1cs_to_qap_reduction(self, m, poly_m, index):
        poly_list = []

        for i in range(len(m[0])):

            x = [0] * len(m)
            y = [0] * len(m)

            for j in range(len(m)):
                x[j] = (j + 1) % self.p
                y[j] = m[j][i]

            # Instead recalculate the interpolation
            # we lookup the result from the cache
            if tuple(x + y) in interpolation_cache:
                coeff = interpolation_cache[tuple(x + y)]
            else:
                poly = lagrange_polynomial(x, y, self.p)
                coeff = poly.coeffs()

                if len(coeff) < len(x):
                    coeff += [0] * (len(x) - len(coeff))

                interpolation_cache[tuple(x + y)] = coeff

            poly_list.append(coeff)

        poly_m[index] = poly_list

    def from_r1cs(self, A: list, B: list, C: list, n_public: int):
        """
        Parse QAP from R1CS matrices

        Args:
            A, B, C: Matrix A,B,C from R1CS compile result
            n_public: Number of public variables in R1CS
        """
        mat = (A, B, C)
        self.n_public = n_public

        poly_m = [[]] * 3

        for i, m in enumerate(mat):
            self._r1cs_to_qap_reduction(m, poly_m, i)

        self.U, self.V, self.W = poly_m[0], poly_m[1], poly_m[2]
        self.T = vanishing_polynomial(len(poly_m[0][0]), self.p)

        # Clear all caches
        interpolation_cache.clear()
        clear_cache()

    def evaluate_witness(self, witness: list):
        """
        Evaluate QAP with witness vector. Incorrect witness value will raise an error.

        Args:
            witness: Witness vector (public+private) to be evaluated

        Return:
            U, V, W, H: Resulting polynomials to be proved
        """

        poly_m = []
        for m in (self.U, self.V, self.W):
            result = []
            # dot product of <witness> . [poly_list]

            for i in range(len(m[0])):
                result += [sum(witness[j] * m[j][i] for j in range(len(witness)))]

            poly_m.append(PolynomialRing(result, self.p))

        U, V, W = poly_m[0], poly_m[1], poly_m[2]

        H, remainder = (U * V - W) / self.T
        if not remainder.is_zero():
            raise ValueError("(U * V - W) / T did not divide to zero")

        return U, V, W, H
