import hashlib
from .ecc import EllipticCurve, ispointG1, ispointG2


def hash_to_scalar(data: bytes, domain_separation_tag: bytes, curve: str = 'BN254'):
    E = EllipticCurve(curve)
    return E.curve.PointG1.hash_to_field(domain_separation_tag, data)


def hash_to_curve(data: bytes, domain_separation_tag: bytes, curve: str = 'BN254', size: int = 1):

    E = EllipticCurve(curve)

    points = []
    for _ in range(size):
        point = E.curve.PointG1.hash_to_curve(domain_separation_tag, data)
        points.append(point)

        # TODO: might not be the best practice to chain hash
        data = point.to_bytes()

    return points[0] if size == 1 else points

class FiatShamirTranscript:

    def __init__(self, label: bytes, alg='sha256'):
        self.alg = alg
        self.label = label
        self.hasher = hashlib.new(alg, label)
        self.state = []

    def reset(self):
        self.hasher = hashlib.new(self.alg, self.label)

    def append(self, data):
        
        if isinstance(data, bytes):
            self.hasher.update(data)
        elif isinstance(data, str):
            self.hasher.update(data.encode())
        elif isinstance(data, int):
            data = int.to_bytes(data, data.bit_length(), 'big')
            self.hasher.update(data)
        elif data and isinstance(data, list) and isinstance(data[0], int):
            for d in data:
                d = int.to_bytes(d, d.bit_length(), 'big')
                self.hasher.update(d)
        elif ispointG1(data) or ispointG2(data):
            self.hasher.update(bytes(data.to_bytes()))
        elif data and isinstance(data, list) and (ispointG1(data[0]) or ispointG2(data[0])):
            for d in data:
                self.hasher.update(bytes(d.to_bytes()))
        else:
            raise TypeError(f"Type of {type(data)} is not supported as transcript")

    def get_challenge(self) -> bytes:
        digest = self.hasher.digest()
        return digest

    def get_challenge_scalar(self) -> int:
        return int.from_bytes(self.get_challenge(), 'big')