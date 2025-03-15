import hashlib
from .base import VectorCommitmentScheme

class Merkle(VectorCommitmentScheme):

    def __init__(self, alg='blake2b'):
        super().__init__()
        self.alg = alg

    def setup(self):
        pass

    def _hash(self, data):
        return hashlib.new(self.alg, data).digest()

    def _build_tree(self, nodes):
        tree = [nodes]
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                new_level.append(self._hash(left + right))
            nodes = new_level
            tree.append(nodes)
        return tree

    def commit(self, vector):
        leaves = [self._hash(data) for data in vector]
        tree = self._build_tree(leaves)

        return tree[-1][0]

    def open(self, vector, index):
        leaves = [self._hash(data) for data in vector]
        tree = self._build_tree(leaves)
        proof = []
        for level in tree[:-1]:
            sibling_index = index ^ 1
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            index //= 2
        return proof

    def verify(self, commitment, proof, index, element):
        current_hash = self._hash(element)
        for sibling_hash in proof:
            if index % 2 == 0:
                current_hash = self._hash(current_hash + sibling_hash)
            else:
                current_hash = self._hash(sibling_hash + current_hash)
            index //= 2
        return current_hash == commitment
