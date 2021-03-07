import os
from django.conf import settings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.files.uploadhandler import FileUploadHandler

class EncryptedFileUploadHandler(FileUploadHandler):
    """Encrypt data as it is uploaded"""
    def __init__(self, request=None):
        super().__init__(request=request)
        self.nonce = os.urandom(16)
        self.encryptor = Cipher(algorithms.AES(settings.AES_KEY),modes.CTR(self.nonce)).encryptor()
        self.nonce_passed = False

    def receive_data_chunk(self, raw_data, start):
        if not self.nonce_passed:
            self.nonce_passed = True
            return self.nonce + self.encryptor.update(raw_data)
        else:
            return self.encryptor.update(raw_data)
    
    def file_complete(self, file_size):
        return


