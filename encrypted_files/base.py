import os
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from django.core.files import File

class EncryptedFile(File):
    BLOCK_SIZE = 16

    def __init__(self, file, key=None):
        super().__init__(file,name=None)
        self.key = key or settings.AES_KEY
        self.counter = 0
        self.offset = 0

        pos = self.file.tell()
        self.file.seek(0)
        self.nonce = self.file.read(self.BLOCK_SIZE)
        self.seek(pos)
    
    def __iter__(self):
        while True:
            data = self.read(self.DEFAULT_CHUNK_SIZE)
            if not data:
                break
            yield data
    
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
        size_w_ofset = size + self.offset
        new_offset = size_w_ofset % self.BLOCK_SIZE

        if size < 0:
            full_size = -1
            new_offset = self.size % self.BLOCK_SIZE
        elif size == 0:
            return b""
        elif new_offset != 0:
            full_size = size_w_ofset - new_offset + self.BLOCK_SIZE
        else:
            # multiple of 16
            full_size = size_w_ofset

        encrypted_data = self.file.read(full_size)
        decrypted_data = self.decryptor.update(encrypted_data)

        self.counter += (len(encrypted_data) - (self.BLOCK_SIZE if new_offset!=0 else 0)) // self.BLOCK_SIZE
        
        if size < 0:
            return_data = decrypted_data[self.offset :]
        else:
            return_data = decrypted_data[self.offset : self.offset + size]
            if new_offset != 0:
                self.file.seek(-self.BLOCK_SIZE,os.SEEK_CUR)
        self.offset = new_offset
        return return_data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Seek to a position in the decrypted buffer"""
        if whence==os.SEEK_SET:
            pos = offset
        elif whence==os.SEEK_CUR:
            pos = offset + self.tell()
        elif whence==os.SEEK_END:
            pos = offset + self.size - self.BLOCK_SIZE
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