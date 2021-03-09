from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .base import EncryptedFile
import os
import io
from hypothesis.extra.django import TestCase
from hypothesis import given, strategies as st


class TestSymmetry(TestCase):
    def setUp(self):
        key = os.urandom(32)
        decrypted = b"\xff"*130399
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
    
    @given(st.integers(min_value=-1,max_value=130399))
    def test_read(self,size):
        self.read_test(size)
    
    @given(st.integers(min_value=0,max_value=130399),st.just(0))
    def test_seek(self,offset,whence):
        self.seek(offset,whence)
        self.tell_test()
    
    @given(st.integers(min_value=0,max_value=130399),st.integers(-1,130399))
    def test_seek_then_read(self,offset,size):
        self.seek(offset)
        self.read_test(size)

    @given(st.integers(min_value=0,max_value=130399),st.integers(-1,130399))
    def test_read_then_seek(self,offset,size):
        self.read(size)
        self.seek(offset)
        self.tell_test()