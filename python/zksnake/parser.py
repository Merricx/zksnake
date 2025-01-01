import csv
from io import BytesIO
from pathlib import Path
from ._algebra import circuit

SUPPORTED_VERSION = [1]


class R1CSReader:

    def __init__(self, r1csfile: str, symfile: str = None):
        file = Path(r1csfile)
        self.reader = file.open("rb")

        self.version = None
        self.n_section = None
        self.header = {}
        self.wire_label_map = {}
        self.wires = []
        self.raw_constraints = []
        self.constraints = []

        self.symbol_map = {}
        if symfile:
            with Path(symfile).open("r", encoding="utf-8") as f:
                self.__read_symfile(f)

    def __read_symfile(self, file):
        csv_reader = csv.reader(file, delimiter=",")
        self.symbol_map["0"] = (0, 1)
        for row in csv_reader:
            label, index, _, name = row
            self.symbol_map[label] = (index, name)

    def __read_header(self):

        magic = self.reader.read(4)
        assert magic == b"r1cs", f"Invalid magic bytes: {magic}"

        self.version = int.from_bytes(self.reader.read(4), "little")
        self.n_section = int.from_bytes(self.reader.read(4), "little")

        assert (
            self.version in SUPPORTED_VERSION
        ), f"Unsupported r1cs file version: {self.version}"

    def __read_section(self):
        while True:

            section_type = int.from_bytes(self.reader.read(4), "little") or 0
            section_size = int.from_bytes(self.reader.read(8), "little")
            section_content = BytesIO(self.reader.read(section_size))

            if section_type == 1:
                self.__read_header_section(section_content)
            elif section_type == 2:
                self.raw_constraints.append(section_content)
            elif section_type == 3:
                self.__read_wire_to_label_section(section_content)
            elif section_type == 0:
                break

    def __read_header_section(self, content: BytesIO):

        fs = int.from_bytes(content.read(4), "little")
        prime = int.from_bytes(content.read(fs), "little")

        n_wires = int.from_bytes(content.read(4), "little")
        n_pub_out = int.from_bytes(content.read(4), "little")
        n_pub_in = int.from_bytes(content.read(4), "little")
        n_priv_in = int.from_bytes(content.read(4), "little")
        n_labels = int.from_bytes(content.read(8), "little")
        m_constraints = int.from_bytes(content.read(4), "little")

        self.header = {
            "fs": fs,
            "prime": prime,
            "n_wires": n_wires,
            "n_pub_out": n_pub_out,
            "n_pub_in": n_pub_in,
            "n_priv_in": n_priv_in,
            "n_labels": n_labels,
            "m_constraints": m_constraints,
        }

    def __read_constraint_section(self, content: BytesIO):

        assigned_wire_id = []
        for _ in range(self.header["m_constraints"]):
            a = 0
            b = 0
            c = 0
            rhs_c = 0
            rhs_c_multiplier = 0
            current_rhs_wire_id = -1

            n_a = int.from_bytes(content.read(4), "little")
            for _ in range(n_a):
                wire_id = int.from_bytes(content.read(4), "little")
                factor = int.from_bytes(
                    content.read(self.header["fs"]), "little")

                sym = self.wires[wire_id]
                if a:
                    a += factor * sym
                else:
                    a = factor * sym

            n_b = int.from_bytes(content.read(4), "little")
            for _ in range(n_b):
                wire_id = int.from_bytes(content.read(4), "little")
                factor = int.from_bytes(
                    content.read(self.header["fs"]), "little")

                sym = self.wires[wire_id]
                if b:
                    b += factor * sym
                else:
                    b = factor * sym

            n_c = int.from_bytes(content.read(4), "little")
            for _ in range(n_c):
                wire_id = int.from_bytes(content.read(4), "little")
                factor = int.from_bytes(
                    content.read(self.header["fs"]), "little")

                sym = self.wires[wire_id]
                if rhs_c:
                    if (
                        wire_id > current_rhs_wire_id
                        and wire_id not in assigned_wire_id
                    ):
                        current_rhs_wire_id = wire_id
                        assigned_wire_id.append(wire_id)
                        if c:
                            c += rhs_c_multiplier * rhs_c
                        else:
                            c = rhs_c_multiplier * rhs_c

                        rhs_c = sym
                        rhs_c_multiplier = factor
                    else:
                        if c:
                            c += factor * sym
                        else:
                            c = factor * sym
                else:
                    current_rhs_wire_id = wire_id
                    rhs_c = sym
                    rhs_c_multiplier = factor
                    assigned_wire_id.append(wire_id)

            if c:
                eq = rhs_c_multiplier * rhs_c + c == a * b
            else:
                eq = rhs_c_multiplier * rhs_c == a * b

            self.constraints.append(eq)

    def __read_wire_to_label_section(self, content: BytesIO):
        index = 0
        while True:
            label = content.read(8)
            if not label:
                break

            self.wire_label_map[index] = int.from_bytes(label, "little")
            index += 1

    def __construct_constraints(self):

        if self.symbol_map:
            self.wires = [1] + [None] * (self.header["n_wires"] - 1)
            for i, (_, value) in enumerate(self.symbol_map.items()):
                index, name = value
                index = int(index)
                if index > 0:
                    self.wires[index] = circuit.Field(name)
        else:
            public_inputs = [
                circuit.Field(f"pub{i+1}") for i in range(self.header["n_pub_in"])
            ]
            private_inputs = [
                circuit.Field(f"priv{i+1}") for i in range(self.header["n_priv_in"])
            ]
            outputs = [circuit.Field(f"out{i+1}")
                       for i in range(self.header["n_pub_out"])]

            n_intermediate = self.header["n_wires"] - (
                self.header["n_pub_in"]
                + self.header["n_priv_in"]
                + self.header["n_pub_out"]
                + 1
            )
            intermediate_vars = [circuit.Field(f"v{i+1}")
                                 for i in range(n_intermediate)]

            self.wires = (
                [1] + outputs + public_inputs +
                private_inputs + intermediate_vars
            )

        for constraint in self.raw_constraints:
            self.__read_constraint_section(constraint)

    def __close(self):
        self.reader.close()

    def read(self):
        self.__read_header()
        self.__read_section()
        self.__construct_constraints()
        self.__close()

        return {
            "header": self.header,
            "wires": self.wires,
            "constraints": self.constraints,
        }
