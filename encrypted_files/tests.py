from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .base import EncryptedFile
import os
import io
import unittest
# from hypothesis.extra.django import TestCase
from hypothesis import given, strategies as st


SIZE = 59

class TestSymmetry(unittest.TestCase):
    def setUp(self):
        key = os.urandom(32)
        decrypted = b"\xff"*SIZE
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
        encrypted = nonce + cipher.update(decrypted)
        encrypted = io.BytesIO(encrypted)
        encrypted.seek(0)
        self.ef = EncryptedFile(encrypted,key=key)
        self.decrypted = io.BytesIO(decrypted)
    
    def read(self,size=-1):
        return self.decrypted.read(size), self.ef.read(size)
    
    def seek(self,offset,whence=0):
        return self.decrypted.seek(offset,whence), self.ef.seek(offset,whence)
    
    def tell_test(self):
        self.assertEqual(self.decrypted.tell(),self.ef.tell())
    
    def read_test(self,size):
        self.assertEqual(*self.read(size))
    
    @given(st.integers(min_value=-1,max_value=SIZE))
    def test_read(self,size):
        self.read_test(size)
    
    @given(st.integers(min_value=0,max_value=SIZE))
    def test_seek(self,offset):
        self.seek(offset)
        self.tell_test()
    
    @given(st.integers(min_value=-SIZE,max_value=0))
    def test_seek_end(self,offset):
        self.seek(offset,os.SEEK_END)
        self.tell_test()
    
    @given(st.integers(min_value=0,max_value=SIZE),st.integers(-1,SIZE))
    def test_seek_then_read(self,offset,size):
        self.seek(offset)
        self.read_test(size)

    @given(st.integers(min_value=0,max_value=SIZE),st.integers(-1,SIZE))
    def test_read_then_seek(self,offset,size):
        self.read(size)
        self.seek(offset)
        self.tell_test()
    
    def test_read_end_negative(self):
        self.read()
        self.read_test(-1)
    
    def test_read_end_positive(self):
        self.read()
        self.read_test(100)

class TestCounterOverflow(TestSymmetry):
    def setUp(self):
        key = os.urandom(32)
        decrypted = b"\xff"*SIZE
        nonce = b"\xff"*16
        cipher = Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
        encrypted = nonce + cipher.update(decrypted)
        encrypted = io.BytesIO(encrypted)
        encrypted.seek(0)
        self.ef = EncryptedFile(encrypted,key=key)
        self.decrypted = io.BytesIO(decrypted)

class TestCounterZero(TestSymmetry):
    def setUp(self):
        key = os.urandom(32)
        decrypted = b"\xff"*SIZE
        nonce = bytes(16)
        cipher = Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
        encrypted = nonce + cipher.update(decrypted)
        encrypted = io.BytesIO(encrypted)
        encrypted.seek(0)
        self.ef = EncryptedFile(encrypted,key=key)
        self.decrypted = io.BytesIO(decrypted)