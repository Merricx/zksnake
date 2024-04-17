from .polynomial import PolynomialRing, lagrange_polynomial

class QAP:

    def __init__(self, p):
        self.U = []
        self.V = []
        self.W = []
        self.T = PolynomialRing([0], p)
        self.n_public = 0

        self.p = p

    def generate_T(self, degree: int):
        """Generate polynomial `T = (x - 1) * (x - 2) * (x - 3) ... (x - n)`"""
        # T = (x - 1) * (x - 2) * (x - 3) ...
        self.T = PolynomialRing([1], self.p)
        for i in range(1, degree + 1):
            self.T *= PolynomialRing([-i, 1], self.p)

    def from_r1cs(self, A: list, B: list, C: list, n_public: int):
        """
        Parse QAP from R1CS matrices

        Args:
            A, B, C: Matrix A,B,C from R1CS compile result
            n_public: Number of public variables in R1CS
        """
        mat = (A, B, C)
        self.n_public = n_public
        
        poly_m = []
        for m in mat:
            poly_list = []
            for i in range(len(m[0])):
                x = [0] * len(m)
                y = [0] * len(m)

                for j in range(len(m)):
                    x[j] = (j + 1) % self.p
                    y[j] = m[j][i]

                poly = lagrange_polynomial(x, y, self.p)
                poly_list.append(poly.coeffs)

            poly_m.append(poly_list)

        self.U, self.V, self.W = poly_m
        self.generate_T(len(poly_m[0][0]))
        
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

        U, V, W = poly_m

        H, remainder = (U * V - W) / self.T
        if not remainder.is_zero():
            raise ValueError("(U * V - W) / T did not divide to zero")
        
        return U, V, W, H