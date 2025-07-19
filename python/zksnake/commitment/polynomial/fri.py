from ...polynomial import Polynomial, get_all_evaluation_points
from ...subprotocol.fri import FRI
from ...transcript import FiatShamirTranscript
from ...utils import next_power_of_two
from .base import PolynomialCommitmentScheme


class FRI_PCS(PolynomialCommitmentScheme):
    """
    FRI protocol as Polynomial Commitment Scheme
    """

    def __init__(
        self,
        max_degree,
        field,
        folding_factor=2,
        last_layer_degree_bound=1,
        pow_bits=20,
        hash_alg="blake2b",
    ):
        super().__init__(max_degree, field)
        self.name = "FRI"
        self.n = next_power_of_two(max_degree)
        self.max_degree = max_degree
        self.order = field
        self.bit_length = 32
        self.hash_alg = hash_alg

        self.inner_fri = FRI(
            max_degree, field, folding_factor, last_layer_degree_bound, pow_bits
        )

    def setup(self):
        pass

    def _quotienting(self, polynomial, point):
        evaluation = polynomial(point)
        divisor_poly = Polynomial([-point % self.order, 1], self.order)
        quotient_poly, remainder = (polynomial - evaluation) / divisor_poly
        if not remainder.is_zero():
            raise ValueError("Given polynomial is not divided to zero")

        return quotient_poly, evaluation

    def commit(self, polynomial, point, transcript=None):

        assert polynomial.degree() <= self.max_degree, "Polynomial exceeds max degree"

        q_poly, _ = self._quotienting(polynomial, point)

        evaluations = []
        for element in get_all_evaluation_points(self.inner_fri.n, self.order):
            evaluations.append(q_poly(element))

        transcript = transcript or FiatShamirTranscript(self.name, self.order)
        self.inner_fri.init_transcript(transcript)

        commitment, codewords = self.inner_fri.commit(evaluations, transcript)

        return commitment, codewords

    def open(self, codewords, transcript):
        return self.inner_fri.query(codewords, transcript)

    def verify(self, commitment, proof, transcript=None):
        transcript = transcript or FiatShamirTranscript(self.name, self.order)
        return self.inner_fri.verify(commitment, proof, transcript)

    def zero_commitment(self):
        raise NotImplementedError("Zero commitment is not implemented")

    def multi_open(self, points_query, transcript=None):
        raise NotImplementedError("Multi-open is not implemented")

    def multi_verify(self, points_query, proof, transcript=None):
        raise NotImplementedError("Multi-verify is not implemented")
