from typing import List, Sequence

from zksnake.constant import BN254_SCALAR_FIELD

from .sumcheck import Sumcheck, SumcheckPolynomial
from ..polynomial import MultilinearPolynomial, PolynomialRing, get_all_root_of_unity, ifft
from ..transcript import FiatShamirTranscript

class GkrPolynomial(SumcheckPolynomial):
    """
    Multilinear Polynomial that is used at each sumcheck round in GKR protocol.
    
    The polynomial is as follows:

    $f(a,b,c) = add(a, b, c) * (W(b) + W(c)) + mul(a, b, c) * (W(b) * W(c))$
    """
    def __init__(self, n, p, add_i, mul_i, w_b, w_c):
        super().__init__(n, p)
        self.add_i = add_i
        self.mul_i = mul_i
        self.w_b = w_b
        self.w_c = w_c
        self.mlpoly = None

    def to_evaluations(self):
        evals = []

        add_i = self.add_i.to_evaluations()
        mul_i = self.mul_i.to_evaluations()
        w_b = self.w_b.to_evaluations()
        w_c = self.w_c.to_evaluations()

        idx = 0
        for b, value_b in enumerate(w_b):
            for c, value_c in enumerate(w_c):
                idx = (c << self.w_b.num_vars) | b
                if add_i[idx] or mul_i[idx]:
                    result = (
                        add_i[idx] * (value_b + value_c) +
                        mul_i[idx] * (value_b * value_c)
                    ) % self.p
                    evals.append(result)
                    # sparse_eval.append((idx, result))
                else:
                    evals.append(0)
                # idx += 1

        return evals

    def partial_evaluate(self, points):
        b = points[:min(self.w_b.num_vars, len(points))]
        c = points[self.w_b.num_vars:]
        add_i = self.add_i.partial_evaluate(points)
        mul_i = self.mul_i.partial_evaluate(points)
        w_b = self.w_b.partial_evaluate(b)
        w_c = self.w_c.partial_evaluate(c)

        return GkrPolynomial(self.n, self.p, add_i, mul_i, w_b, w_c)

    def evaluate(self, points):

        evaluated = self.partial_evaluate(points)

        add_i = evaluated.add_i.to_evaluations()[0]
        mul_i = evaluated.mul_i.to_evaluations()[0]
        w_b = evaluated.w_b.to_evaluations()[0]
        w_c = evaluated.w_c.to_evaluations()[0]

        return (add_i * (w_b + w_c) + mul_i * (w_b * w_c)) % self.p

    def to_univariate(self):

        evals = []
        roots = get_all_root_of_unity(3, self.p)
        for i in roots:
            s = sum(self.partial_evaluate([i]).to_evaluations()) % self.p
            evals.append(s)

        coeffs = ifft(evals, self.p)

        return PolynomialRing(coeffs, self.p)

    def first_round(self):
        g1 = self.to_univariate()
        return g1

    def round_function(self, r):
        fixed = self.partial_evaluate(r)
        uni_poly = fixed.to_univariate()

        return uni_poly

class LayeredCircuit:
    def __init__(self, inputs: List[str]):
        self.layers = [[]]  # List of layers, where each layer is a list of gates
        self.inputs = inputs  # Dictionary to store inputs to the circuit
        self._used_vars = []
        self._current_layer = 0
        self._allowed_inputs = set(inputs)

    def add_layer(self):
        """
        Add new layer
        """
        if self.layers[self._current_layer]:
            allowed_inputs = set()
            for _, input1, input2, output in self.layers[self._current_layer]:
                allowed_inputs.add(output)
                self._used_vars.extend([input1, input2, output])

            self._allowed_inputs = allowed_inputs
            self.layers.append([])
            self._current_layer += 1

    def add_gate(self, gate_type, input1, input2, output):
        """
        Add new gate to the current layer
        """
        if gate_type in ["ADD", "MUL"]:
            if input1 not in self._allowed_inputs or input2 not in self._allowed_inputs:
                raise ValueError(
                    f"Gate inputs {input1}, {input2} must be from outputs from previous layers or inputs from first layer"
                )

            if output in self._used_vars:
                raise ValueError(f"Variable already used in another layer: {output}")

            self.layers[self._current_layer].append((gate_type, input1, input2, output))
        else:
            raise ValueError("Invalid gate type")

    def add(self, input1, input2, output):
        """Short for `add_gate("ADD", input1, input2, output)`"""
        self.add_gate('ADD', input1, input2, output)

    def mul(self, input1, input2, output):
        """Short for `add_gate("MUL", input1, input2, output)`"""
        self.add_gate('MUL', input1, input2, output)

    def get_wire_label(self):
        """
        Get label of variables at each layer
        """
        labels = []
        for layer in self.layers:
            current_layer_label = []
            for _, input1, input2, _ in layer:
                current_layer_label.extend([input1, input2])

            current_layer_label = list(dict.fromkeys(current_layer_label))
            labels.append(current_layer_label)

        outputs = []
        for _, _, _, out in self.layers[-1]:
            outputs.append(out)

        labels.append(outputs)

        return labels

    def evaluate(self, input_map: dict, modulus: int) -> Sequence[dict]:
        """Evaluate the layered circuit and return all wires value."""
        values = input_map.copy()  # Start with input values
        eval_layers = [input_map.copy()]

        if set(input_map.keys()) != set(self.inputs):
            raise ValueError("Insufficient input values are supplied")

        for layer in self.layers:
            current_layer_eval = {}
            for gate_type, input1, input2, output in layer:
                # Retrieve input values
                val1 = values[input1]
                val2 = values[input2]

                # Perform gate operation
                result = 0
                if gate_type == 'ADD':
                    result = (val1 + val2) % modulus
                elif gate_type == 'MUL':
                    result = val1 * val2 % modulus

                values[output] = result
                current_layer_eval[output] = result

            eval_layers.append(current_layer_eval)

        return eval_layers


class GKR:
    """
    GKR protocol 
    (Goldwasser, Kalai, and Rothblum. 2008. 
    *Delegating Computation: Interactive Proofs for Muggles*)

    Prove the evaluation of small depth Layered Circuit.
    
    The implementation follows algorithm from Justin Thaler's 
    "Proofs, Arguments, and Zero-Knowledge", section 4.6.
    """

    def __init__(self, circuit: LayeredCircuit, field=BN254_SCALAR_FIELD, transcript=None):
        self.circuit = circuit
        self.order = field
        self.depth = len(circuit.layers)
        self.wire_labels = self.circuit.get_wire_label()[::-1]
        self.transcript = transcript or FiatShamirTranscript(b'GKR')

        # print("wire label", self.wire_labels)

    def _add_i(self, i):
        target_layer = self.circuit.layers[::-1][i]
        next_layer_wire = self.wire_labels[i+1]

        non_zero_evals = []
        for index, gate in enumerate(target_layer):
            gate_type, in1, in2, _ = gate

            if gate_type == "ADD":
                a = index
                b = next_layer_wire.index(in1)
                c = next_layer_wire.index(in2)

                non_zero_evals.append((a, b, c))

        return non_zero_evals

    def _mul_i(self, i):
        target_layer = self.circuit.layers[::-1][i]
        next_layer_wire = self.wire_labels[i+1]

        non_zero_evals = []
        for index, gate in enumerate(target_layer):
            gate_type, in1, in2, _ = gate

            if gate_type == "MUL":
                a = index
                b = next_layer_wire.index(in1)
                c = next_layer_wire.index(in2)

                non_zero_evals.append((a, b, c))

        return non_zero_evals

    def _selector_polynomial(self, i, r):
        num_vars_i = len(self.wire_labels[i])
        num_vars_next_i = len(self.wire_labels[i+1])
        selector_num_vars = num_vars_i + num_vars_next_i * 2

        add_i_evals = []
        mul_i_evals = []

        for a, b, c in self._add_i(i):
            index = c * (2**num_vars_next_i * 2**num_vars_i) + b * 2**num_vars_i + a
            add_i_evals.append((index, 1))

        for a, b, c in self._mul_i(i):
            index = c * (2**num_vars_next_i * 2**num_vars_i) + b * 2**num_vars_i + a
            mul_i_evals.append((index, 1))

        add_ext_i = MultilinearPolynomial(selector_num_vars, add_i_evals, self.order)
        add_ext_i = add_ext_i.partial_evaluate(r)

        mul_ext_i = MultilinearPolynomial(selector_num_vars, mul_i_evals, self.order)
        mul_ext_i = mul_ext_i.partial_evaluate(r)

        return add_ext_i, mul_ext_i

    def _sumcheck_polynomial(self, evaluation_layers, i, r):

        w_evals = []
        num_vars_next_i = len(self.wire_labels[i+1])

        for index, k in enumerate(self.wire_labels[i+1]):
            w_evals.append((index, evaluation_layers[i+1][k]))

        add_ext_i, mul_ext_i = self._selector_polynomial(i, r)
        w_i = MultilinearPolynomial(num_vars_next_i, w_evals, self.order)

        # print(add_ext_i)
        # print(mul_ext_i)
        # print(w_i)

        return GkrPolynomial(add_ext_i.num_vars, self.order, add_ext_i, mul_ext_i, w_i, w_i)

    def _init_transcript(self, input_map, outputs):
        self.transcript.reset()
        for _, v in input_map.items():
            self.transcript.append(v)
        for _, output in outputs:
            self.transcript.append(output)

    def _get_transcript_challenge(self, length):
        challenges = []
        for _ in range(length):
            r = self.transcript.get_challenge_scalar() % self.order
            self.transcript.append(r)
            challenges.append(r)

        return challenges

    def _restrict_to_line(self, w, b, c):
        n = w.num_vars
        assert len(b) == n and len(c) == n

        k = [(val_c - val_b) % self.order for val_b, val_c in zip(b, c) ]
        w_evals = w.to_evaluations()

        def recursive_restrict(evals, b, k, idx):
            if idx == len(b):
                return PolynomialRing([evals[0]], self.order)

            mid = len(evals) // 2
            poly_low = recursive_restrict(evals[:mid], b, k, idx + 1)
            poly_hi = recursive_restrict(evals[mid:], b, k, idx + 1)

            t = PolynomialRing([b[idx], k[idx]], self.order)
            return poly_low + (poly_hi - poly_low) * t

        return recursive_restrict(w_evals, b, k, 0)

    def prove(self, input_map: dict):
        """
        Evaluate and prove layered circuit using GKR protocol
        with provided `input_map`
        """

        # print("circuit", self.circuit.layers[::-1])

        sumcheck_proofs = []
        evaluation_layers = self.circuit.evaluate(input_map, self.order)[::-1]
        # print("evaluation layers:", evaluation_layers)

        # P sends the output vector and claims that w = W_0
        outputs = []
        for i, (_,v) in enumerate(evaluation_layers[0].items()):
            outputs.append((i, v))
        n = len(outputs)
        w_0 = MultilinearPolynomial(max(1, n), outputs, self.order)

        # V sends random r0 and computes m0 = w(r0)
        self._init_transcript(input_map, outputs)
        r = self._get_transcript_challenge(n)
        m = w_0.evaluate(r)
        # print(m)

        for i in range(self.depth):
            # print('layer', i)
            f = self._sumcheck_polynomial(evaluation_layers, i, r)
            # print(sum(f.to_evaluations()) % self.order)
            n_next = f.n // 2
            b = self._get_transcript_challenge(n_next)
            c = self._get_transcript_challenge(n_next)

            # P and V apply sumcheck on the relation between W_0 and W_1
            sumcheck = Sumcheck(f.n, self.order)
            challenges = b + c
            sum_claim, proof = sumcheck.prove_arbitrary(f, challenges)
            assert sum_claim == m, "Wiring pattern of the circuit might be incorrect"

            l = [PolynomialRing(
                [b_val, (c_val - b_val) % self.order], self.order)
                for b_val, c_val in zip(b, c)]
            q = self._restrict_to_line(f.w_b, b[::-1], c[::-1])
            z1 = q(0)
            z2 = q(1)

            w_eval = (
                f.add_i.evaluate(challenges) * (z1 + z2) +
                f.mul_i.evaluate(challenges) * (z1 * z2)
            ) % self.order

            assert w_eval == proof[-1](challenges[-1])

            _ = [self.transcript.append(p.coeffs()) for p in proof]
            self.transcript.append(q.coeffs())
            self.transcript.append([z1, z2])

            proof.append((q, z1, z2))
            sumcheck_proofs.append(proof)

            r = self._get_transcript_challenge(1)[0]
            l_r = [p(r) for p in l]
            assert f.w_b.evaluate(l_r) == q(r)

            m = q(r)
            r = l_r

        return evaluation_layers[0], sumcheck_proofs


    def verify(self, input_map: dict, output_map: dict, proofs: list) -> bool:
        """
        Verify the proof of the correctness of layered circuit evaluation
        with provided `input_map` and `output_map` as input and output, respectively.
        """
        outputs = []
        for i, v in enumerate(output_map.values()):
            outputs.append((i, v))
        n = len(outputs)
        w = MultilinearPolynomial(max(1, n), outputs, self.order)

        # V sends random r0 and computes m0 = w(r0)
        self._init_transcript(input_map, outputs)
        r = self._get_transcript_challenge(n)
        m = w.evaluate(r)

        for i in range(self.depth):
            # print('layer', i)
            add_ext_i, mul_ext_i = self._selector_polynomial(i, r)

            n_next = add_ext_i.num_vars // 2
            b = self._get_transcript_challenge(n_next)
            c = self._get_transcript_challenge(n_next)

            sumcheck = Sumcheck(add_ext_i.num_vars, self.order)
            challenges = b + c

            round_proof = proofs[i]
            if not sumcheck.verify(m, round_proof[:-1], challenges):
                return False

            # last sumcheck round
            l = [PolynomialRing(
                [b_val, (c_val - b_val) % self.order], self.order)
                for b_val, c_val in zip(b, c)]
            q, z1, z2 = round_proof[-1]
            if q(0) != z1 or q(1) != z2:
                return False

            last_proof = round_proof[-2]
            w_eval = (
                add_ext_i.evaluate(challenges) * (z1 + z2) +
                mul_ext_i.evaluate(challenges) * (z1 * z2)
            ) % self.order
            if w_eval != last_proof(challenges[-1]):
                return False

            _ = [self.transcript.append(p.coeffs()) for p in round_proof[:-1]]
            self.transcript.append(q.coeffs())
            self.transcript.append([z1, z2])

            r = self._get_transcript_challenge(1)[0]
            l_r = [p(r) for p in l]

            m = q(r)
            r = l_r

        inputs = []
        for i, v in enumerate(input_map.values()):
            inputs.append((i, v))

        w_d = MultilinearPolynomial(len(inputs), inputs, self.order)
        if w_d.evaluate(r) != m:
            return False

        return True
