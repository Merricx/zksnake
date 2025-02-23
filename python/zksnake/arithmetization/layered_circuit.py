from typing import List, Sequence


class LayeredCircuit:
    """
    Simple Layered Arithmetic Circuit to be used in GKR protocol.
    """

    def __init__(self, inputs: List[str]):
        self.layers = [[]]
        self.inputs = inputs
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
                    f"Gate inputs {input1}, {input2} must be from outputs "
                    + "from previous layers or inputs from first layer"
                )

            if output in self._used_vars:
                raise ValueError(f"Variable already used in another layer: {output}")

            self.layers[self._current_layer].append((gate_type, input1, input2, output))
        else:
            raise ValueError("Invalid gate type")

    def add(self, input1, input2, output):
        """Short for `add_gate("ADD", input1, input2, output)`"""
        self.add_gate("ADD", input1, input2, output)

    def mul(self, input1, input2, output):
        """Short for `add_gate("MUL", input1, input2, output)`"""
        self.add_gate("MUL", input1, input2, output)

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
                if gate_type == "ADD":
                    result = (val1 + val2) % modulus
                elif gate_type == "MUL":
                    result = val1 * val2 % modulus

                values[output] = result
                current_layer_eval[output] = result

            eval_layers.append(current_layer_eval)

        return eval_layers
