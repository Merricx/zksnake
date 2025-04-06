import hashlib

from ..commitment.vector import Merkle
from ..polynomial import Polynomial, get_evaluation_point, ifft
from ..transcript import FiatShamirTranscript
from ..utils import is_power_of_two


class FRI:

    def __init__(
        self,
        max_degree,
        domain,
        field,
        folding_factor=2,
        last_layer_degree_bound=255,
        pow_bits=20,
        hash_alg="blake2b",
    ):
        self.n = domain
        self.max_degree = max_degree
        self.order = field
        self.bit_length = 32
        self.hash_alg = hash_alg
        self.merkle_tree = Merkle(hash_alg)

        # FRI optimizations (https://eprint.iacr.org/2021/582.pdf, Section 3.11)
        assert is_power_of_two(folding_factor)
        assert last_layer_degree_bound >= 1
        assert 20 <= pow_bits <= 50

        self.folding_factor = folding_factor
        self.last_layer_degree_bound = last_layer_degree_bound
        self.pow_bits = pow_bits

    def _fold(self, codeword: list[int], challenge: int):

        folded = []
        for i in range(len(codeword) // 2):
            x = get_evaluation_point(len(codeword), i, self.order)
            fx = codeword[i]
            fx_neg = codeword[len(codeword) // 2 + i]

            folded += [
                (
                    (fx + fx_neg) * pow(2, -1, self.order)
                    + challenge * (fx - fx_neg) * pow(2 * x, -1, self.order)
                )
                % self.order
            ]

        return folded

    def _merkle_commit(self, codeword: list[int]):
        # Construct merkle tree such that w and its negative (-w)
        # are in same merkle leave:
        #    ()             ()                ()
        #  /    \         /    \            /    \
        # w     -w      w^2    -w^2        w^3    -w^3
        codeword_bytes = []
        for i in range(len(codeword) // 2):
            codeword_bytes += [
                codeword[i].to_bytes(self.bit_length)
                + codeword[len(codeword) // 2 + i].to_bytes(self.bit_length)
            ]

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

    def commit(self, codeword: list[int], transcript: FiatShamirTranscript = None):

        transcript = transcript or FiatShamirTranscript(b"FRI", self.order)

        commitment = []
        folded_codewords = []

        while len(codeword) > self.last_layer_degree_bound + 1:

            root, codeword_bytes = self._merkle_commit(codeword)

            transcript.append(root)
            folded_codewords.append(codeword_bytes)
            alpha = transcript.get_challenge_scalar()
            print(f"{alpha=}")

            commitment.append(root)
            codeword = self._fold(codeword, alpha)
            print(codeword)

        # in last layer, send polynomial in the clear
        last_poly_coeff = ifft(codeword, self.order)
        transcript.append(last_poly_coeff)
        commitment.append(last_poly_coeff)

        return commitment, folded_codewords

    def query(self, codewords, transcript: FiatShamirTranscript):

        grinding_challenge = transcript.get_challenge()
        proof_of_work = self._grinding(grinding_challenge)
        print(f"{proof_of_work=}")
        transcript.append(proof_of_work)

        opening_proof = [proof_of_work]
        current_domain = self.n
        s = transcript.get_challenge_scalar() % self.n

        # correlated spot check
        for i in range(len(codewords)):

            print("domain:", current_domain)
            print("index:", s)

            if s >= current_domain // 2:
                s -= current_domain // 2

            current_layer = codewords[i]

            target = current_layer[s]

            first_bytes, second_bytes = (
                target[: self.bit_length],
                target[self.bit_length :],
            )
            first_eval = int.from_bytes(first_bytes, "big")
            second_eval = int.from_bytes(second_bytes, "big")

            current_layer_proof = self.merkle_tree.open(current_layer, s)
            current_domain //= 2
            s %= current_domain

            print(f"{first_eval=}")
            print(f"{second_eval=}")
            print(f"{current_layer_proof=}")

            opening_proof.append((current_layer_proof, target))

        return opening_proof

    def prove(self, codeword: list[int], transcript: FiatShamirTranscript = None):

        assert len(codeword) <= self.max_degree + 1
        # pad the codeword
        codeword = codeword + [0 for _ in range(self.max_degree - len(codeword) - 1)]

        transcript = transcript or FiatShamirTranscript(b"FRI", self.order)

        commitment, folded_codewords = self.commit(codeword, transcript)

        opening_proof = self.query(folded_codewords, transcript)

        return commitment, opening_proof

    def _get_fri_layer_evaluation(self, merkle_root, proof, index):

        opening_proof, evaluation_bytes = proof

        first_bytes, second_bytes = (
            evaluation_bytes[: self.bit_length],
            evaluation_bytes[self.bit_length :],
        )
        first_eval = int.from_bytes(first_bytes, "big")
        second_eval = int.from_bytes(second_bytes, "big")

        assert self.merkle_tree.verify(
            merkle_root, opening_proof, index, evaluation_bytes
        )

        return first_eval, second_eval

    def verify(self, commitment, proof, transcript=None):

        transcript = transcript or FiatShamirTranscript(b"FRI", self.order)

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
        index = transcript.get_challenge_scalar() % self.n
        current_domain = self.n
        prev_layer_eval = 0

        for i in range(1, len(proof)):

            if index >= current_domain // 2:
                index -= current_domain // 2

            first_eval, second_eval = self._get_fri_layer_evaluation(
                merkle_roots[i - 1], proof[i], index
            )

            if i > 1:
                assert prev_layer_eval == first_eval or prev_layer_eval == second_eval

            prev_layer_eval = (
                (first_eval + second_eval) * pow(2, -1, self.order)
                + alphas[i - 1]
                * (first_eval - second_eval)
                * pow(
                    2 * get_evaluation_point(current_domain, index, self.order),
                    -1,
                    self.order,
                )
            ) % self.order

            current_domain //= 2
            index = index % current_domain

        assert prev_layer_eval == last_poly(
            get_evaluation_point(current_domain, index, self.order)
        )

        return True
