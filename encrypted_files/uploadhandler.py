import os
from django.conf import settings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.files.uploadhandler import FileUploadHandler

class EncryptedFileUploadHandler(FileUploadHandler):
    """Encrypt data as it is uploaded"""
    def __init__(self, request=None, key=None):
        super().__init__(request=request)
        self.key = key or settings.AES_KEY
    
    def generate_nonce(self):
        return os.urandom(16)
    
    def new_file(self, *args, **kwargs):
        self.nonce = self.generate_nonce()
        self.encryptor = Cipher(algorithms.AES(self.key),modes.CTR(self.nonce)).encryptor()
        self.nonce_passed = False
        return super().new_file(*args,**kwargs)

    def receive_data_chunk(self, raw_data, start):
        if not self.nonce_passed:
            self.nonce_passed = True
            return self.nonce + self.encryptor.update(raw_data)
        else:
            return self.encryptor.update(raw_data)
    
    def file_complete(self, file_size):
        return


