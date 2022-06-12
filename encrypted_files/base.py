import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from django.core.files import File
from django.utils.functional import cached_property


class EncryptedFile(File):
    BLOCK_SIZE = 16

    def __init__(self, file, key=None):
        super().__init__(file, name=None)
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

    @staticmethod
    def add_int_to_bytes(b: bytes, i: int) -> bytes:
        """Add an integer to a byte string"""
        # OpenSSL uses big-endian for CTR
        # If the counter overflows, it wraps back to zero
        i = int.from_bytes(b, byteorder="big") + i
        # Get number of bytes needed to represent the un-wrapped int
        length = (i.bit_length() + 7) >> 3  # same as // 8
        length = max(16, length)
        # cast to bytes and use the last 16 to get the wrapped bytes without modulo
        b = i.to_bytes(length, "big")
        return b[-16:]

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

    @cached_property
    def size(self):
        return super().size - self.BLOCK_SIZE

    def read(self, size: int = -1) -> bytes:
        """Read and decrypt bytes from the buffer"""
        # Return right away if no bytes requested
        if size == 0:
            return b""
        else:
            # read data, zero-pad with offset bytes at start
            encrypted_data = self.file.read(size)
            decrypted_data = self.decryptor.update(bytes(self.offset) + encrypted_data)
            to_return = decrypted_data[self.offset :]
            self.counter, self.offset = divmod(self.tell(), self.BLOCK_SIZE)
            return to_return

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Seek to a position in the decrypted buffer"""
        if whence == os.SEEK_SET:
            pos = offset
        elif whence == os.SEEK_CUR:
            pos = offset + self.tell()
        elif whence == os.SEEK_END:
            pos = offset + self.size
        else:
            raise NotImplementedError(f"Whence of '{whence}' is not supported.")
        # Move the cursor to the start of the block
        # Keep track of how far into the current block we are
        self.counter, self.offset = divmod(pos, self.BLOCK_SIZE)
        self.file.seek(pos + self.BLOCK_SIZE)
        return pos

    def tell(self) -> int:
        # Remove the nonce bytes from the cursor position
        return self.file.tell() - self.BLOCK_SIZE