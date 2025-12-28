import hashlib

from ...commitment.vector import Merkle
from ...polynomial import (
    Polynomial,
    get_all_evaluation_points,
    get_evaluation_point,
    fft,
    ifft,
)
from ...transcript import FiatShamirTranscript
from ...utils import is_power_of_two, next_power_of_two


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
        blowup_factor=8,
        folding_factor=2,
        last_layer_degree_bound=1,
        pow_bits=20,
        num_queries=2,
        hash_alg="blake2b",
    ):
        self.name = b"FRI"
        self.max_degree = max_degree
        self.order = field
        self.elem_size = 32
        self.hash_alg = hash_alg
        self.merkle_tree = Merkle(hash_alg)

        assert is_power_of_two(max_degree + 1)
        assert is_power_of_two(blowup_factor) and blowup_factor >= 2
        assert is_power_of_two(folding_factor)
        assert last_layer_degree_bound >= 0
        assert 20 <= pow_bits <= 50
        assert num_queries >= 1

        self.domain = blowup_factor * (max_degree + 1)
        self.blowup_factor = blowup_factor
        self.num_queries = num_queries
        self.folding_factor = folding_factor
        self.last_layer_degree_bound = last_layer_degree_bound
        self.pow_bits = pow_bits

        self._validate_folding_schedule()

    def init_transcript(self, transcript: FiatShamirTranscript):
        transcript.append(self.domain)
        transcript.append(self.elem_size)
        transcript.append(self.folding_factor)
        transcript.append(self.last_layer_degree_bound)
        transcript.append(self.pow_bits)
        transcript.append(self.num_queries)

    def _validate_folding_schedule(self):
        current_size = self.domain
        if current_size == 0:
            raise ValueError("FRI domain must be non-zero")
        while current_size > self.last_layer_degree_bound + 1:
            if current_size % self.folding_factor != 0:
                raise ValueError("FRI domain must be divisible by folding factor")
            current_size //= self.folding_factor
            if current_size == 0 and self.last_layer_degree_bound != 0:
                raise ValueError("FRI folding reduced domain to zero")

    def get_security_bits(self):
        """
        Returns the soundness bits of this FRI instance based on the
        [ethSTARK](https://eprint.iacr.org/2021/582) conjecture.
        """
        return self.num_queries * (self.blowup_factor.bit_length() - 1) + self.pow_bits

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
        # Construct merkle tree such that coset (w^i, -w^i)
        # are in same merkle leaf
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
                leave += codeword[index].to_bytes(self.elem_size, "big")

            codeword_bytes += [leave]

        return self.merkle_tree.commit(codeword_bytes), codeword_bytes

    def _grinding(self, challenge: bytes):

        target = 1 << (self.elem_size * 8 - self.pow_bits)
        nonce = 0

        while True:
            value = hashlib.new(
                self.hash_alg,
                str(nonce).encode() + challenge,
                digest_size=self.elem_size,
            ).digest()
            hash_int = int.from_bytes(value, byteorder="big")

            if hash_int < target:
                return nonce

            nonce += 1

    def _verify_pow(self, nonce: int, challenge: bytes):

        target = 1 << (self.elem_size * 8 - self.pow_bits)
        value = hashlib.new(
            self.hash_alg, str(nonce).encode() + challenge, digest_size=self.elem_size
        ).digest()
        hash_int = int.from_bytes(value, byteorder="big")

        return hash_int < target

    def _get_fri_layer_evaluation(self, merkle_root, proof, index):

        opening_proof, evaluation_bytes = proof

        if len(evaluation_bytes) != self.folding_factor * self.elem_size:
            raise ValueError("Invalid FRI evaluation bytes length")

        if not self.merkle_tree.verify(
            merkle_root, opening_proof, index, evaluation_bytes
        ):
            raise ValueError("Invalid FRI Merkle opening proof")

        coset_evaluations = []
        for _ in range(self.folding_factor):
            evaluation = int.from_bytes(evaluation_bytes[: self.elem_size], "big")
            evaluation_bytes = evaluation_bytes[self.elem_size :]
            coset_evaluations.append(evaluation)

        return coset_evaluations

    def commit(self, codeword: list[int], transcript: FiatShamirTranscript = None):

        transcript = transcript or FiatShamirTranscript(self.name, self.order)

        if len(codeword) != self.domain:
            raise ValueError(
                f"Invalid codeword length {len(codeword)}; expected {self.domain}"
            )
        if len(codeword) & (len(codeword) - 1) != 0:
            raise ValueError("Codeword length must be a power of two")
        if (len(codeword) // self.folding_factor) == 0:
            raise ValueError("Codeword length too small for folding factor")

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
        query_openings = []

        for _ in range(self.num_queries):
            current_domain = self.domain // self.folding_factor
            s = transcript.get_challenge_scalar() % current_domain

            per_query_opening = []
            # correlated spot check
            for i in range(len(codewords)):

                current_layer = codewords[i]
                target = current_layer[s]

                current_layer_proof = self.merkle_tree.open(current_layer, s)
                per_query_opening.append((current_layer_proof, target))

                if current_domain >= self.folding_factor:
                    current_domain //= self.folding_factor

                s %= current_domain

            query_openings.append(per_query_opening)

        if self.num_queries == 1:
            opening_proof.extend(query_openings[0])
        else:
            opening_proof.append(query_openings)

        return opening_proof

    def prove(self, polynomial, transcript: FiatShamirTranscript = None):

        assert polynomial.degree() <= self.max_degree

        transcript = transcript or FiatShamirTranscript(self.name, self.order)
        self.init_transcript(transcript)

        codeword = fft(polynomial.coeffs(), self.order, self.domain)

        commitment, folded_codewords = self.commit(codeword, transcript)

        opening_proof = self.query(folded_codewords, transcript)

        return commitment, opening_proof

    def verify(self, commitment, proof, transcript=None):

        transcript = transcript or FiatShamirTranscript(self.name, self.order)
        self.init_transcript(transcript)

        merkle_roots = commitment[:-1]
        last_poly_coeffs = commitment[-1]
        last_poly = Polynomial(last_poly_coeffs, self.order)

        if self.num_queries == 1:
            if len(proof) - 1 != len(merkle_roots):
                raise ValueError("FRI proof length does not match commitment")
            query_proofs = [proof[1:]]
        else:
            if len(proof) != 2:
                raise ValueError("FRI proof length does not match commitment")
            query_proofs = proof[1]
            if len(query_proofs) != self.num_queries:
                raise ValueError("FRI query count does not match proof")
            for query_proof in query_proofs:
                if len(query_proof) != len(merkle_roots):
                    raise ValueError("FRI proof length does not match commitment")

        if last_poly.degree() > self.last_layer_degree_bound:
            raise ValueError("Last FRI layer polynomial exceeds allowed degree bound")

        expected_final_domain = self.domain // (
            self.folding_factor ** len(merkle_roots)
        )
        if len(last_poly_coeffs) != expected_final_domain:
            raise ValueError("Last FRI layer size does not match expected domain")

        alphas = []
        for root in merkle_roots:
            transcript.append(root)
            alphas.append(transcript.get_challenge_scalar())

        transcript.append(last_poly_coeffs)

        nonce = proof[0]
        grinding_challenge = transcript.get_challenge()
        if not self._verify_pow(nonce, grinding_challenge):
            raise ValueError("Invalid FRI proof-of-work nonce")

        transcript.append(nonce)

        for _, query_proof in enumerate(query_proofs):
            current_domain = self.domain // self.folding_factor
            index = transcript.get_challenge_scalar() % current_domain
            initial_evaluation = None
            prev_layer_eval = 0
            expected_slot = None

            for i in range(1, len(query_proof) + 1):

                coset_evaluations = self._get_fri_layer_evaluation(
                    merkle_roots[i - 1], query_proof[i - 1], index
                )

                if len(coset_evaluations) != self.folding_factor:
                    raise ValueError("Invalid number of coset evaluations in FRI proof")

                if expected_slot is not None:
                    if expected_slot >= len(coset_evaluations):
                        raise ValueError(
                            f"Invalid coset index {expected_slot} for layer {i}"
                        )
                    if coset_evaluations[expected_slot] != prev_layer_eval:
                        raise ValueError(
                            "Mismatch between folded evaluation and committed coset"
                        )

                alpha = alphas[i - 1] % self.order
                apow = 1
                acc = 0
                for evaluation in coset_evaluations:
                    acc = (acc + evaluation * apow) % self.order
                    apow = (apow * alpha) % self.order
                prev_layer_eval = acc

                if i != len(query_proof):
                    child_domain = current_domain // self.folding_factor
                    if child_domain == 0:
                        raise ValueError("FRI domain collapsed to zero")
                    expected_slot = index // child_domain
                    if i == 1:
                        initial_evaluation = coset_evaluations[expected_slot]

                    current_domain = child_domain
                    index %= current_domain
                else:
                    expected_slot = None

            expected = last_poly(
                get_evaluation_point(current_domain, index, self.order)
            )
            if prev_layer_eval != expected:
                raise ValueError("Final FRI consistency check failed")

            if initial_evaluation is None:
                initial_evaluation = expected

        return True
