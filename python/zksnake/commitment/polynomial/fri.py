from ...polynomial import (
    Polynomial,
    get_evaluation_point,
    coset_fft,
)
from ...subprotocol.ldt import FRI
from ...transcript import FiatShamirTranscript
from .base import MultiOpeningQuery, PolynomialCommitmentScheme


class FRI_PCS(PolynomialCommitmentScheme):
    """
    FRI-based Polynomial Commitment Scheme using DEEP-FRI.

    Commit to polynomial f by Merkle-committing its coset evaluations.
    Open at point z by proving the quotient q = (f - f(z)) / (X - z)
    is low-degree via FRI, with a DEEP consistency check linking q to f.
    """

    def __init__(
        self,
        max_degree,
        field,
        offset=1,
        blowup_factor=8,
        folding_factor=2,
        last_layer_degree_bound=1,
        pow_bits=20,
        num_queries=2,
        hash_alg="blake2b",
    ):
        super().__init__(max_degree, field)
        self.name = b"FRI-PCS"
        self.max_degree = max_degree
        self.order = field
        self.hash_alg = hash_alg
        self.is_setup = True

        self.inner_fri = FRI(
            max_degree,
            field,
            offset=offset,
            blowup_factor=blowup_factor,
            folding_factor=folding_factor,
            last_layer_degree_bound=last_layer_degree_bound,
            pow_bits=pow_bits,
            num_queries=num_queries,
            hash_alg=hash_alg,
        )

    def setup(self):
        pass

    def commit(self, polynomial, transcript=None):
        if polynomial.degree() > self.max_degree:
            raise ValueError("Polynomial exceeds max degree")

        codeword = coset_fft(
            polynomial.coeffs(),
            self.inner_fri.offset,
            self.order,
            self.inner_fri.domain,
        )

        root, leaves = self.inner_fri._merkle_commit(codeword)
        return root, (codeword, leaves)

    def open(self, polynomial, point, commitment, prover_state, transcript=None):
        if polynomial.degree() > self.max_degree:
            raise ValueError("Polynomial exceeds max degree")

        f_root = commitment
        _, f_leaves = prover_state
        p = self.order
        fri = self.inner_fri

        evaluation = polynomial(point)

        # Compute quotient q = (f - v) / (X - z)
        divisor = Polynomial([-point % p, 1], p)
        quotient, remainder = (polynomial - evaluation) / divisor
        if not remainder.is_zero():
            raise ValueError("Polynomial division has non-zero remainder")

        # Evaluate q on the FRI coset domain
        q_codeword = coset_fft(
            quotient.coeffs(),
            fri.offset,
            p,
            fri.domain,
        )

        # Build transcript
        transcript = transcript or FiatShamirTranscript(self.name, p)
        fri.init_transcript(transcript)
        transcript.append(f_root)
        transcript.append(point)
        transcript.append(evaluation)

        # FRI commit phase on q
        q_commitment, q_folded_codewords = fri.commit(q_codeword, transcript)

        # Query phase: open both f and q at same positions
        q_proof, extra_openings = fri.query(
            q_folded_codewords, transcript, extra_codewords=[f_leaves]
        )
        f_openings = [eo[0] for eo in extra_openings]

        # Extract q query openings from FRI proof format
        pow_nonce = q_proof[0]
        if fri.num_queries == 1:
            q_query_openings = [q_proof[1:]]
        else:
            q_query_openings = q_proof[1]

        proof = [pow_nonce, q_commitment, f_openings, q_query_openings]
        return proof, evaluation

    def _deep_check(self, f_coset_evals, q_coset_evals, s, z, v):
        """Verify q(x_j) * (x_j - z) + v == f(x_j) at all coset positions."""
        fri = self.inner_fri
        p = self.order
        m = fri.domain // fri.folding_factor
        for j in range(fri.folding_factor):
            idx = s + j * m
            x_j = fri.offset * get_evaluation_point(fri.domain, idx, p) % p
            lhs = (q_coset_evals[j] * ((x_j - z) % p) + v) % p
            if lhs != f_coset_evals[j]:
                raise ValueError(
                    "DEEP consistency check failed: q(x)*(x-z)+v != f(x)"
                )

    def verify(self, commitment, proof, point, evaluation, transcript=None):
        f_root = commitment
        z = point
        v = evaluation
        p = self.order
        fri = self.inner_fri

        # Validate proof structure
        if not isinstance(proof, (list, tuple)) or len(proof) != 4:
            raise ValueError("Invalid FRI-PCS proof structure")

        pow_nonce, q_commitment, f_openings, q_query_openings = proof

        if not isinstance(q_commitment, (list, tuple)) or len(q_commitment) < 1:
            raise ValueError("Invalid q commitment in proof")
        if (
            not isinstance(f_openings, (list, tuple))
            or len(f_openings) != fri.num_queries
        ):
            raise ValueError("FRI-PCS proof has wrong number of f openings")
        if (
            not isinstance(q_query_openings, (list, tuple))
            or len(q_query_openings) != fri.num_queries
        ):
            raise ValueError("FRI-PCS proof has wrong number of q query openings")

        # Build transcript with PCS-specific data
        transcript = transcript or FiatShamirTranscript(self.name, p)
        fri.init_transcript(transcript)
        transcript.append(f_root)
        transcript.append(z)
        transcript.append(v)

        # Reuse FRI's commitment verification (degree check + transcript replay)
        q_merkle_roots, q_last_poly, alphas = fri._verify_commitment_phase(
            q_commitment, transcript
        )
        num_rounds = len(q_merkle_roots)

        # Validate per-query layer counts
        for qi in range(fri.num_queries):
            if (
                not isinstance(q_query_openings[qi], (list, tuple))
                or len(q_query_openings[qi]) != num_rounds
            ):
                raise ValueError("FRI proof layer count does not match commitment")

        # Reuse FRI's PoW verification
        fri._verify_pow_phase(pow_nonce, transcript)

        # Query verification
        for qi in range(fri.num_queries):
            s = transcript.get_challenge_scalar() % (
                fri.domain // fri.folding_factor
            )

            # Verify f's Merkle opening
            f_coset_evals = fri._get_fri_layer_evaluation(
                f_root, f_openings[qi], s
            )

            # DEEP consistency check
            if num_rounds > 0:
                q_first_evals = fri._get_fri_layer_evaluation(
                    q_merkle_roots[0], q_query_openings[qi][0], s
                )
            else:
                # Zero FRI rounds: evaluate q directly at coset positions
                m = fri.domain // fri.folding_factor
                q_first_evals = []
                for j in range(fri.folding_factor):
                    idx = s + j * m
                    x_j = (
                        fri.offset
                        * get_evaluation_point(fri.domain, idx, p)
                        % p
                    )
                    q_first_evals.append(q_last_poly(x_j))

            self._deep_check(f_coset_evals, q_first_evals, s, z, v)

            # Reuse FRI's per-query layer verification
            fri._verify_query_phase(
                q_query_openings[qi], s, q_merkle_roots, alphas, q_last_poly
            )

        return True

    def _init_multi_transcript(self, points_query, transcript):
        """Initialize transcript for multi-open/verify with commitments and evaluations."""
        fri = self.inner_fri
        p = self.order

        transcript = transcript or FiatShamirTranscript(self.name, p)
        fri.init_transcript(transcript)
        for comm in points_query.commitments:
            transcript.append(comm)

        for point, commitments in points_query.get_commitments():
            for commitment in commitments:
                evaluation = points_query.get_evaluation(commitment, point)
                transcript.append(evaluation)

        alpha = transcript.get_challenge_scalar()
        return transcript, alpha

    def multi_open(self, points_query, transcript=None):
        p = self.order
        fri = self.inner_fri

        verifier_query = points_query.to_verifier_query()

        transcript, alpha = self._init_multi_transcript(verifier_query, transcript)

        # Compute batched quotient polynomial:
        # q(x) = Σ α^i * (f_i(x) - v_i) / (x - z_i)
        q_poly = Polynomial([0], p)
        alpha_power = 1
        for point, polys in points_query.get_polynomials():
            for poly in polys:
                evaluation = poly(point)
                divisor = Polynomial([-point % p, 1], p)
                quotient, remainder = (poly - evaluation) / divisor
                if not remainder.is_zero():
                    raise ValueError("Polynomial division has non-zero remainder")
                q_poly += alpha_power * quotient
                alpha_power = alpha_power * alpha % p

        # Evaluate q on the FRI coset domain
        q_codeword = coset_fft(q_poly.coeffs(), fri.offset, p, fri.domain)

        # FRI commit on q
        q_commitment, q_folded_codewords = fri.commit(q_codeword, transcript)

        # Recompute each polynomial's Merkle leaves for opening
        all_f_leaves = []
        for poly in points_query.polynomials:
            codeword = coset_fft(poly.coeffs(), fri.offset, p, fri.domain)
            _, leaves = fri._merkle_commit(codeword)
            all_f_leaves.append(leaves)

        # Query: open q layers and all f_i at same positions
        q_proof, extra_openings = fri.query(
            q_folded_codewords, transcript, extra_codewords=all_f_leaves
        )

        # Repack into proof structure
        pow_nonce = q_proof[0]
        if fri.num_queries == 1:
            q_query_openings = [q_proof[1:]]
        else:
            q_query_openings = q_proof[1]

        proof = [pow_nonce, q_commitment, extra_openings, q_query_openings]
        return proof, verifier_query

    def multi_verify(self, points_query, proof, transcript=None):
        p = self.order
        fri = self.inner_fri

        if not isinstance(proof, (list, tuple)) or len(proof) != 4:
            raise ValueError("Invalid FRI-PCS multi proof structure")

        pow_nonce, q_commitment, f_openings, q_query_openings = proof

        num_polys = len(points_query.commitments)

        transcript, alpha = self._init_multi_transcript(points_query, transcript)

        # Verify FRI commitment phase on q
        q_merkle_roots, q_last_poly, alphas = fri._verify_commitment_phase(
            q_commitment, transcript
        )
        num_rounds = len(q_merkle_roots)

        # Validate proof shapes
        if len(f_openings) != fri.num_queries:
            raise ValueError("FRI-PCS multi proof has wrong number of query openings")
        if len(q_query_openings) != fri.num_queries:
            raise ValueError("FRI-PCS multi proof has wrong number of q query openings")
        for qi in range(fri.num_queries):
            if len(f_openings[qi]) != num_polys:
                raise ValueError(
                    "FRI-PCS multi proof has wrong number of f openings per query"
                )
            if (
                not isinstance(q_query_openings[qi], (list, tuple))
                or len(q_query_openings[qi]) != num_rounds
            ):
                raise ValueError("FRI proof layer count does not match commitment")

        fri._verify_pow_phase(pow_nonce, transcript)

        for qi in range(fri.num_queries):
            s = transcript.get_challenge_scalar() % (
                fri.domain // fri.folding_factor
            )

            # Verify all f_i Merkle openings
            f_coset_evals_list = []
            for pi in range(num_polys):
                f_evals = fri._get_fri_layer_evaluation(
                    points_query.commitments[pi], f_openings[qi][pi], s
                )
                f_coset_evals_list.append(f_evals)

            # Get q's first-layer coset evaluations
            if num_rounds > 0:
                q_first_evals = fri._get_fri_layer_evaluation(
                    q_merkle_roots[0], q_query_openings[qi][0], s
                )
            else:
                m = fri.domain // fri.folding_factor
                q_first_evals = []
                for j in range(fri.folding_factor):
                    idx = s + j * m
                    x_j = (
                        fri.offset
                        * get_evaluation_point(fri.domain, idx, p)
                        % p
                    )
                    q_first_evals.append(q_last_poly(x_j))

            # Batched DEEP consistency check (multiplication form):
            # q(x_j) · Π_z(x_j - z) == Σ_i α^i · (f_i(x_j) - v_i) · Π_{z'≠z_i}(x_j - z')
            # This avoids division, preventing failure when x_j == z_i.
            m = fri.domain // fri.folding_factor
            coset_x = []
            for j in range(fri.folding_factor):
                idx = s + j * m
                coset_x.append(
                    fri.offset * get_evaluation_point(fri.domain, idx, p) % p
                )

            distinct_points = []
            for pt, _ in points_query.get_commitments():
                if pt not in distinct_points:
                    distinct_points.append(pt)

            for j in range(fri.folding_factor):
                xj = coset_x[j]

                vanishing = 1
                for pt in distinct_points:
                    vanishing = vanishing * ((xj - pt) % p) % p
                lhs = q_first_evals[j] * vanishing % p

                rhs = 0
                alpha_power = 1
                for pt, commitments in points_query.get_commitments():
                    cofactor = 1
                    for other_pt in distinct_points:
                        if other_pt != pt:
                            cofactor = cofactor * ((xj - other_pt) % p) % p
                    for commitment in commitments:
                        pi = points_query.commitments.index(commitment)
                        v = points_query.get_evaluation(commitment, pt)
                        numerator = (f_coset_evals_list[pi][j] - v) % p
                        rhs = (rhs + alpha_power * numerator * cofactor) % p
                        alpha_power = alpha_power * alpha % p

                if lhs != rhs:
                    raise ValueError(
                        "DEEP consistency check failed in multi-verify"
                    )

            # Verify q's FRI layers
            fri._verify_query_phase(
                q_query_openings[qi], s, q_merkle_roots, alphas, q_last_poly
            )

        return True

    def zero_commitment(self):
        raise NotImplementedError("Zero commitment is not implemented")
