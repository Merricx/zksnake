import hashlib

from ..commitment.vector import Merkle
from ..polynomial import Polynomial, get_evaluation_point, ifft
from ..transcript import FiatShamirTranscript
from ..utils import is_power_of_two, next_power_of_two


class FRI:
    """
    FRI protocol (Fast Reed-Solomon Interactive Oracle Proofs of Proximity)
    (https://eccc.weizmann.ac.il/report/2017/134/)

    with the proof optimizations based on ethSTARK documentation
    (https://eprint.iacr.org/2021/582, Section 3.11)
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
        self.n = next_power_of_two(max_degree)
        self.max_degree = max_degree
        self.order = field
        self.bit_length = 32
        self.hash_alg = hash_alg
        self.merkle_tree = Merkle(hash_alg)

        assert is_power_of_two(folding_factor)
        assert last_layer_degree_bound >= 1
        assert 20 <= pow_bits <= 50

        self.folding_factor = folding_factor
        self.last_layer_degree_bound = last_layer_degree_bound
        self.pow_bits = pow_bits

    def init_transcript(self, transcript: FiatShamirTranscript):
        transcript.append(self.n)
        transcript.append(self.bit_length)
        transcript.append(self.folding_factor)
        transcript.append(self.last_layer_degree_bound)
        transcript.append(self.pow_bits)

    def _fold(self, codeword: list[int], challenge: int):

        next_domain = len(codeword) // self.folding_factor

        folded = []
        for i in range(next_domain):
            acc = 0
            for j in range(self.folding_factor):
                index = (i + j * next_domain) % len(codeword)
                acc = (
                    acc + codeword[index] * pow(challenge, j, self.order)
                ) % self.order
            folded.append(acc)

        return folded

    def _merkle_commit(self, codeword: list[int]):
        # Construct merkle tree such that all coset w
        # are in same merkle leave
        #
        # If folding_factor=2:
        #    ()             ()                ()
        #  /    \         /    \            /    \
        # w     -w      w^2    -w^2        w^3    -w^3
        codeword_bytes = []
        next_domain = len(codeword) // self.folding_factor

        for i in range(next_domain):
            leave = b""
            for j in range(self.folding_factor):
                index = (i + j * next_domain) % len(codeword)
                leave += codeword[index].to_bytes(self.bit_length)

            codeword_bytes += [leave]

        return self.merkle_tree.commit(codeword_bytes), codeword_bytes

    def _grinding(self, challenge: bytes):

        target = 1 << (self.bit_length * 8 - self.pow_bits)
        nonce = 0

        while True:
            value = hashlib.new(
                self.hash_alg,
                str(nonce).encode() + challenge,
                digest_size=self.bit_length,
            ).digest()
            hash_int = int.from_bytes(value, byteorder="big")

            if hash_int < target:
                return nonce

            nonce += 1

    def _verify_pow(self, nonce: int, challenge: bytes):

        target = 1 << (self.bit_length * 8 - self.pow_bits)
        value = hashlib.new(
            self.hash_alg, str(nonce).encode() + challenge, digest_size=self.bit_length
        ).digest()
        hash_int = int.from_bytes(value, byteorder="big")

        return hash_int < target

    def _get_fri_layer_evaluation(self, merkle_root, proof, index):

        opening_proof, evaluation_bytes = proof

        assert len(evaluation_bytes) == self.folding_factor * self.bit_length

        assert self.merkle_tree.verify(
            merkle_root, opening_proof, index, evaluation_bytes
        )

        coset_evaluations = []
        for _ in range(self.folding_factor):
            evaluation = int.from_bytes(evaluation_bytes[: self.bit_length], "big")
            evaluation_bytes = evaluation_bytes[self.bit_length :]
            coset_evaluations.append(evaluation)

        return coset_evaluations

    def commit(self, codeword: list[int], transcript: FiatShamirTranscript = None):

        transcript = transcript or FiatShamirTranscript(b"FRI", self.order)

        commitment = []
        folded_codewords = []

        while len(codeword) > self.last_layer_degree_bound + 1:

            root, codeword_bytes = self._merkle_commit(codeword)

            transcript.append(root)
            folded_codewords.append(codeword_bytes)
            alpha = transcript.get_challenge_scalar()

            commitment.append(root)
            codeword = self._fold(codeword, alpha)

        # in last layer, send polynomial in the clear
        last_poly_coeff = ifft(codeword, self.order)
        transcript.append(last_poly_coeff)
        commitment.append(last_poly_coeff)

        return commitment, folded_codewords

    def query(self, codewords, transcript: FiatShamirTranscript):

        grinding_challenge = transcript.get_challenge()
        proof_of_work = self._grinding(grinding_challenge)

        transcript.append(proof_of_work)

        opening_proof = [proof_of_work]
        current_domain = self.n // self.folding_factor
        s = transcript.get_challenge_scalar() % current_domain

        # correlated spot check
        for i in range(len(codewords)):

            current_layer = codewords[i]
            target = current_layer[s]

            current_layer_proof = self.merkle_tree.open(current_layer, s)

            if current_domain >= self.folding_factor:
                current_domain //= self.folding_factor

            s %= current_domain

            opening_proof.append((current_layer_proof, target))

        return opening_proof

    def prove(self, codeword: list[int], transcript: FiatShamirTranscript = None):

        assert len(codeword) <= self.max_degree + 1
        # pad the codeword
        codeword = codeword + [0 for _ in range(self.max_degree + 1 - len(codeword))]

        transcript = transcript or FiatShamirTranscript(b"FRI", self.order)
        self.init_transcript(transcript)

        commitment, folded_codewords = self.commit(codeword, transcript)

        opening_proof = self.query(folded_codewords, transcript)

        return commitment, opening_proof

    def verify(self, commitment, proof, transcript=None):

        transcript = transcript or FiatShamirTranscript(b"FRI", self.order)
        self.init_transcript(transcript)

        merkle_roots = commitment[:-1]
        last_poly = Polynomial(commitment[-1], self.order)

        assert last_poly.degree() <= self.last_layer_degree_bound

        alphas = []
        for root in merkle_roots:
            transcript.append(root)
            alphas.append(transcript.get_challenge_scalar())

        transcript.append(last_poly.coeffs())

        nonce = proof[0]
        grinding_challenge = transcript.get_challenge()
        assert self._verify_pow(nonce, grinding_challenge)

        transcript.append(nonce)
        current_domain = self.n // self.folding_factor
        index = transcript.get_challenge_scalar() % current_domain
        prev_layer_eval = 0

        for i in range(1, len(proof)):

            coset_evaluations = self._get_fri_layer_evaluation(
                merkle_roots[i - 1], proof[i], index
            )

            if i > 1:
                assert prev_layer_eval in coset_evaluations

            prev_layer_eval = 0
            for j, evaluation in enumerate(coset_evaluations):
                prev_layer_eval = (
                    prev_layer_eval + pow(alphas[i - 1], j, self.order) * evaluation
                ) % self.order

            if i != len(proof) - 1:
                current_domain //= self.folding_factor
                index %= current_domain

        assert prev_layer_eval == last_poly(
            get_evaluation_point(current_domain, index, self.order)
        )

        return True
