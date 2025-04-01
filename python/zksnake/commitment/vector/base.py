class VectorCommitmentScheme:

    def __init__(self):
        self.order = None

    def setup(self):
        raise NotImplementedError()

    def commit(self, vector):
        raise NotImplementedError()

    def open(self, vector, index):
        raise NotImplementedError()

    def verify(self, commitment, proof, index, element):
        raise NotImplementedError()