import unittest
from hashlib import sha256
import secrets
from BLOCKCHAIN1 import Block, Blockchain, User, BlockchainApp


class Block:
    def __init__(self, number=0, previous_hash="0" * 64, data=None, nonce=0):
        self.number = number
        self.previous_hash = previous_hash
        self.data = data
        self.nonce = nonce

    def hash(self):
        hashing_text = str(self.number) + self.previous_hash + str(self.data) + str(self.nonce)
        h = sha256()
        h.update(hashing_text.encode('utf-8'))
        return h.hexdigest()

    def __str__(self):
        return f"Block#: {self.number}\nHash: {self.hash()}\nPrevious: {self.previous_hash}\nData: {self.data}\nNonce: {self.nonce}\n"

class Blockchain:
    difficulty = 4

    def __init__(self):
        self.chain = []

    def add(self, block):
        self.chain.append(block)

    def mine(self, block):
        if self.chain:
            block.previous_hash = self.chain[-1].hash()
        else:
            block.previous_hash = "0" * 64

        while block.hash()[:self.difficulty] != "0" * self.difficulty:
            block.nonce = secrets.randbits(32)

        self.add(block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            _previous = self.chain[i].previous_hash
            _current = self.chain[i - 1].hash()
            if _previous != _current or _current[:self.difficulty] != "0" * self.difficulty:
                return False
        return True

class TestBlock(unittest.TestCase):
    def test_hash(self):
        block = Block(data="Test data")
        expected_hash = sha256((str(block.number) + block.previous_hash + block.data + str(block.nonce)).encode('utf-8')).hexdigest()
        self.assertEqual(block.hash(), expected_hash)

class TestBlockchain(unittest.TestCase):
    class TestBlock(unittest.TestCase):
     def test_hash(self):
        block = Block(data="Test data")
        expected_hash = sha256((str(block.number) + block.previous_hash + block.data + str(block.nonce)).encode('utf-8')).hexdigest()
        self.assertEqual(block.hash(), expected_hash)

class TestBlockchain(unittest.TestCase):
    def test_is_valid(self):
        blockchain = Blockchain()
        block1 = Block(data="Block 1")
        block2 = Block(data="Block 2")
        blockchain.add(block1)
        blockchain.add(block2)
        self.assertTrue(blockchain.is_valid)

if __name__ == "__main__":
    unittest.main()
