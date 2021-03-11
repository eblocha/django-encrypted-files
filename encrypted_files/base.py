import os
import io
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

    @classmethod
    def add_int_to_bytes(cls, b, i):
        """Add an integer to a byte string"""
        # OpenSSL uses big-endian for CTR
        # If the counter overflows, it wraps back to zero
        i = int.from_bytes(b, byteorder="big") + i
        # Get number of bytes needed to represent the un-wrapped int
        length = (i.bit_length() + 7) >> 3 # same as // 8
        length = max(16,length)
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
            # See how much data is left in the file
            curr_pos = self.tell()
            size_rest = self.size - curr_pos
            get_rest = size < 0 or size >= size_rest
            if get_rest and size_rest:
                # rest of data is requested, read and decrypt it
                encrypted_data = self.file.read()
                decrypted_data = self.decryptor.update(encrypted_data)
                to_return = decrypted_data[self.offset :]
                # get the counter value and offset
                self.counter, self.offset = divmod(size_rest,self.BLOCK_SIZE)
                # Always ensure underlying pointer is at the start of a block
                self.file.seek(-self.offset,os.SEEK_END)
                return to_return
            elif get_rest:
                # No data left
                return b""
            else:
                # Only some of the remaining data was requested
                end_pos = curr_pos + size
                new_counter, new_offset = divmod(end_pos,self.BLOCK_SIZE)
                
                # How many bytes to the end of the block
                to_block_end = self.BLOCK_SIZE - new_offset if new_offset else 0
                
                # decrypt
                encrypted_data = self.file.read(self.offset + size + to_block_end)
                decrypted_data = self.decryptor.update(encrypted_data)
                
                # slice out data to return
                to_return = decrypted_data[self.offset : self.offset + size]
                
                # Seek file back to start of correct block
                self.file.seek(end_pos - new_offset + self.BLOCK_SIZE)

                # Set counter and offset
                self.counter, self.offset = new_counter, new_offset
                
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
        self.counter, self.offset = divmod(pos,self.BLOCK_SIZE)
        self.file.seek(pos - self.offset + self.BLOCK_SIZE)
        return pos

    def tell(self) -> int:
        # The cursor position in the underlying encrypted buffer is always at the start of a block.
        # Add on the offset into the block for arbitrary access
        return self.file.tell() + self.offset - self.BLOCK_SIZE