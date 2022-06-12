from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from encrypted_files.base import EncryptedFile
import os
import io
import unittest
from hypothesis import given, strategies as st


SIZE = 130399

class TestSymmetry(unittest.TestCase):
    def setUp(self):
        key = os.urandom(32)
        decrypted = b"\xff"*SIZE
        nonce = os.urandom(16)
        self.boilerplate(key,decrypted,nonce)
    
    def boilerplate(self,key,decrypted,nonce):
        cipher = Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
        encrypted = nonce + cipher.update(decrypted)
        encrypted = io.BytesIO(encrypted)
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
        self.boilerplate(key,decrypted,nonce)

class TestCounterZero(TestSymmetry):
    def setUp(self):
        key = os.urandom(32)
        decrypted = b"\xff"*SIZE
        nonce = bytes(16)
        self.boilerplate(key,decrypted,nonce)

class TestIerator(unittest.TestCase):
    
    @given(st.integers(0,64 * 1024 * 5))
    def test_iterator(self,size):
        key = os.urandom(32)
        decrypted = b"\xff"*size
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key),modes.CTR(nonce)).encryptor()
        encrypted = nonce + cipher.update(decrypted)
        encrypted = io.BytesIO(encrypted)
        ef = EncryptedFile(encrypted,key=key)
        self.assertEqual(decrypted,b"".join([d for d in ef]))