import hashlib
from .ecc import EllipticCurve


def hash_to_scalar(data: bytes, domain_separation_tag: bytes, modulus: int, alg: str = 'sha256'):
    h = hashlib.new(alg)
    h.update(domain_separation_tag)
    h.update(data)

    return int.from_bytes(h.digest(), 'big') % modulus


def hash_to_curve(data: bytes, domain_separation_tag: bytes, curve: str = 'BN254', size: int = 1, alg: str = 'sha256'):

    E = EllipticCurve(curve)

    h = hashlib.new(alg)
    h.update(domain_separation_tag)
    h.update(data)

    points = []
    for _ in range(size):
        while True:
            digest = h.digest()
            h.update(digest)

            try:
                point = E.curve.PointG1.hash_to_curve(digest)
                points.append(point)
                break
            except ValueError:
                pass

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
            self.hasher.update(bytes(data))

    def get_challenge(self):
        digest = self.hasher.digest()
        return digest
