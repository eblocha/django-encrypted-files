import os
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings

class EncryptedFile:
    BLOCK_SIZE = 16

    def __init__(self, file, key=None):
        self.file = file
        self.key = key or settings.AES_KEY
        self.counter = 0
        self.offset = 0

        pos = self.file.tell()
        self.file.seek(0)
        self.nonce = self.file.read(self.BLOCK_SIZE)
        self.seek(pos)
    
    @classmethod
    def add_int_to_bytes(cls, b, i):
        """Add an integer to a byte string"""
        # OpenSSL uses big-endian for CTR
        MAX = int.from_bytes(b"\xff"*cls.BLOCK_SIZE,byteorder="big") + 1
        # If the counter overflows, it wraps back to zero
        i = (int.from_bytes(b, byteorder="big") + i) % MAX
        return i.to_bytes(cls.BLOCK_SIZE, "big")

    @property
    def cipher(self):
        """We can use this to encrypt/decrypt multiple blocks efficiently."""
        return Cipher(
            algorithms.AES(self.key),
            modes.CTR(self.add_int_to_bytes(self.nonce, self.counter)),
        )

    @property
    def decryptor(self):
        return self.cipher.decryptor()
    
    def read(self, size: int = -1) -> bytes:
        """Read and decrypt bytes from the buffer"""
        # Ensure we are requesting multiples of 16 bytes, unless we are at the end of the stream
        if size == 0:
            return b""
        elif (size > 0) and (size % self.BLOCK_SIZE != 0):
            full_size = size - (size % self.BLOCK_SIZE) + self.BLOCK_SIZE
        else:
            # Whole file is requested, or multiple of 16
            full_size = size

        encrypted_data = self.file.read(full_size)
        decrypted_data = self.decryptor.update(encrypted_data)
        self.counter += len(encrypted_data) // self.BLOCK_SIZE
        if size < 0:
            return decrypted_data[self.offset :]
        else:
            return decrypted_data[self.offset : self.offset + size]

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Seek to a position in the decrypted buffer"""
        if whence==os.SEEK_SET:
            pos = offset
        elif whence==os.SEEK_CUR:
            pos = offset + self.tell()
        else:
            raise NotImplementedError(f"Whence of '{whence}' is not supported.")
        # Move the cursor to the start of the block
        # Keep track of how far into the current block we are
        self.offset = pos % self.BLOCK_SIZE
        real_pos = pos - self.offset
        self.counter = real_pos // self.BLOCK_SIZE
        # bump it 16 more bytes to account for the nonce at the beginning
        real_pos += self.BLOCK_SIZE
        self.file.seek(real_pos)
        return pos
    
    def tell(self) -> int:
        # The cursor position in the underlying encrypted buffer is always at the start of a block.
        # Add on the offset into the block for arbitrary access
        return self.file.tell() + self.offset - self.BLOCK_SIZE