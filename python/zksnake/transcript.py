import hashlib
from .constant import BN254_SCALAR_FIELD
from .ecc import EllipticCurve, ispointG1, ispointG2


def hash_to_scalar(data: bytes, domain_separation_tag: bytes, curve: str = "BN254"):
    E = EllipticCurve(curve)
    return E.curve.PointG1.hash_to_field(domain_separation_tag, data)


def hash_to_curve(
    data: bytes, domain_separation_tag: bytes, curve: str = "BN254", size: int = 1
):

    E = EllipticCurve(curve)

    points = []
    for _ in range(size):
        point = E.curve.PointG1.hash_to_curve(domain_separation_tag, data)
        points.append(point)

        # TODO: might not be the best practice to chain hash
        data = point.to_bytes()

    return points[0] if size == 1 else points


class FiatShamirTranscript:

    def __init__(self, label: bytes = b"", field=BN254_SCALAR_FIELD, alg="blake2b"):
        self.alg = alg
        self.label = label
        self.hasher = hashlib.new(alg, label)
        self.state = []
        self.field = field

    def reset(self):
        self.hasher = hashlib.new(self.alg, self.label)

    def append(self, data):

        data_bytes = b""
        if isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, str):
            data_bytes = data.encode()
        elif isinstance(data, int):
            byte_len = (self.field.bit_length() + 7) // 8
            data_bytes = int.to_bytes(data % self.field, byte_len, "big")
        elif data and isinstance(data, list) and isinstance(data[0], int):
            byte_len = (self.field.bit_length() + 7) // 8
            for d in data:
                d = int.to_bytes(d % self.field, byte_len, "big")
                data_bytes += d
        elif ispointG1(data) or ispointG2(data):
            data_bytes = bytes(data.to_bytes())
        elif (
            data
            and isinstance(data, list)
            and (ispointG1(data[0]) or ispointG2(data[0]))
        ):
            for d in data:
                data_bytes += d.to_bytes()
        else:
            raise TypeError(f"Type of {type(data)} is not supported as transcript")

        self.hasher.update(data_bytes)
        self.state.append(data_bytes)

    def get_hasher_state(self) -> bytes:
        return b"".join(self.state)

    def get_challenge(self) -> bytes:
        digest = self.hasher.digest()
        self.hasher = hashlib.new(self.alg, digest)
        self.state = [digest]
        return digest

    def get_challenge_scalar(self) -> int:
        return int.from_bytes(self.get_challenge(), "big") % self.field
