""" Encrypt - Easy encryption and decryption of secrets
Supplies functions for easy encryption and decryption of data for people that are not very familiar with python or
encryption.
Uses the cryptography Python Package, to de- and encrypt data with AES and 128 bit long keys in CBC mode.
The IV is generated using os.urandom which in Windows uses CryptGenRandom() and is provided in plaintext along with
the encrypted data.
Common usage is provided through the methods:
    encrypt_file
    decrypt_file

"""
import os
from typing import TypeVar, Type

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


T = TypeVar("T")

IV_LEN = 2**7 // 8  # 16 Byte long initialization vector for 128 bit AES

class EncryptedData:
    """ A Class representing encrypted data that can be shared safely.
    Supplies functions for easy encryption and decryption of data for people that are not very familiar with python or
    encryption.
    Uses the cryptography Python Package, to de- and encrypt data with AES and 128 bit long keys in CBC mode.
    The IV is generated using os.urandom which in Windows uses CryptGenRandom() and is provided in plaintext along with
    the encrypted data.
    Common usage is provided through the methods and classmethods of this class.
    """

    def __init__(self, data: bytes, iv: bytes):
        """ Instantiates an Object representing encrypted data.
        Not Commonly used.

        :param data: The Encrypted data.
        :param iv: The Initialization Vector for the Encryption.
        """
        self.data = data
        self.iv = iv

    def __hash__(self):
        return hash(self.iv + self.data)

    def __eq__(self, other) -> bool:
        return isinstance(other, self.__class__) and self.iv == other.iv and self.data == other.data

    @classmethod
    def deserialize(cls: Type[T], data: bytes) -> T:
        """ Deserialize An EncryptedData object.
        Can be used to read a shared secret.

        :param data: The serialized data representing the EncryptedData object.
        :return: A EncryptedData object.
        """
        iv = data[:IV_LEN]
        data_start = IV_LEN
        data = data[data_start:]
        return cls(data=data, iv=iv)

    @classmethod
    def encrypt_data(cls: Type[T], data: bytes, key: bytes) -> T:
        """ Encrypt data that you want to keep a secret.


        :param data: The Data (secret) that should be encrypted.
        :param key: The key to use to encrypt the data.
        :return: A new EncryptedData object.
        """
        padded_data = _Metadata().wrap_data(data)
        iv = os.urandom(IV_LEN)  # Initialization Vector with Windows CryptGenRandom()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        enc_data = encryptor.update(padded_data) + encryptor.finalize()
        return cls(data=enc_data, iv=iv)

    @classmethod
    def encrypt_file(cls: Type[T], path_in: str, key: bytes) -> T:
        """ Encrypt a file, that you want to keep secret.

        :param path_in: The path to the file containing the Data (secret) that should be encrypted.
        :param key: The key to use to encrypt the data.
        :return: A new EncryptedData object.
        """
        with open(path_in, "rb") as file:
            data = file.read()
        return cls.encrypt_data(data, key)

    @classmethod
    def from_file(cls: Type[T], path_in: str) -> T:
        """ Load Encrypted data from a file.
        After that the data can be decrypted with the correct key.

        :param path_in: The path to the file containing the ecrypted data.
        :return: A new EncryptedData object.
        """
        with open(path_in, "rb") as file:
            return cls.deserialize(file.read())

    def decrypt(self, key) -> bytes:
        """ Decrypt this EncryptedData object.
        Decrypt the Data with the ocrrect key to read the secret.
        :param key: The key to decrypt the data with.
        :return: The decrypted secret.
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(self.data) + decryptor.finalize()

        return _Metadata().unwrap_data(padded_data)

    def serialize(self) -> bytes:
        """ Serializes the EncryptedData object to a series of bytes, that can be easily used to share a secret.
        The other end can easily deserialize the object and with the correct key, encrypt and read the secret.
        :return: A bytes representation of the encrypted secret.
        """
        return self.iv + self.data

    def to_file(self, path_out: str):
        """ Write the EncryptedData object to a file for sharing.
        Writes the serialized EncryptedData to a file.
        This file can be safely used for sharing.
        :param path_out: The path to the file into which to write the serialized EncryptedData object.
        """
        with open(path_out, "wb") as file:
            file.write(self.serialize())


def encrypt_file(in_path: str, key: bytes, out_path: str):
    """ Easy Interface for Encrypting a file.
    Encrypt a file to share it safely.

    :param in_path: The path to the file to encrypt.
    :param key: The secret key to use to encrypt the File.
    :param out_path: The path to which to write the encrypted data.
    """
    EncryptedData.encrypt_file(in_path, key).to_file(out_path)


def decrypt_file(in_path: str, key: bytes, out_path: str):
    """ Easy Interface for Decrypting an Encrypted a file.

    :param in_path: The path to the file to decrypt.
    :param key: The secret key to use to decrypt the File.
    :param out_path: The path to which to write the decrypted data.
    """
    EncryptedData.encrypt_file(in_path, key).to_file(out_path)


class _Metadata:
    """ A Class representing Metadata for shared data, including the original data length, as well as checksums and
    other information. Used to pad the data to a integer multiple of the block size.
    """
    _BYTES_RESERVED_FOR_LEN = 4  # Length of the payload is encoded in 4 bytes. Data must be less then 2**32 bytes long.
    _BYTEORDER = "big"  # Big endian byteorder
    _HEADER_BLOCKS = 16  # 16 blocks are used for the header itself, not inlcuding the trailer which is padding.

    def __init__(self, block_size: int = 16):
        """ Instantiate a object that can be used to wrap data with.

        @param block_size: The size of the underlying blocks to which the data should be padded to.
        """
        self.block_size = block_size

    def wrap_data(self, data: bytes) -> bytes:
        """ Wraps the ´data´ with the header and pads it to be a integer multiple of ´block_size´.

        @param data: The original ´data´ to wrap and add padding to.
        @return: The ´data´ wrapped with the header and padding
        """
        return self._generate_header(data) + data + self._generate_padding(len(data))

    def _generate_header(self, data: bytes) -> bytes:
        assert self.block_size >= 5, "The header requires that the block size is at least 5."
        field_length = len(data).to_bytes(self._BYTES_RESERVED_FOR_LEN, self._BYTEORDER, signed=False)
        field_length_hash = checksum(field_length)

        header = bytes()
        # First block is reserved for length and hash of length.
        header = header + field_length
        header = header + b'\x00' * (self.block_size - len(field_length) - len(field_length_hash)) # fill unused
        header = header + field_length_hash  # last byte of first block is currently the checksum

        # Rest of header (hash of the data) is still unimplemented. fill with 0.
        header = header + b'\x00' * self.block_size * (self._HEADER_BLOCKS - 1)  # 15 unused blocks. reserved for hash.
        return header

    def _generate_padding(self, data_len_bytes: int) -> bytes:
        return os.urandom(self._get_pad_len(data_len_bytes))

    def _get_pad_len(self, data_len_bytes) -> int:
        unaligned_bytes = data_len_bytes % self.block_size
        return (self.block_size - unaligned_bytes) % self.block_size

    def _header_parse_data_length(self, wrapped_data: bytes) -> int:
        received_checksum = bytes([wrapped_data[self.block_size - 1]])
        expected_checksum = checksum(wrapped_data[:4])
        if received_checksum != expected_checksum:
            raise DataIntegrityError(f"The received {received_checksum} and expected {expected_checksum} checksums for "
                                     f"the length field do not match")
        return int.from_bytes(wrapped_data[:4], byteorder=self._BYTEORDER, signed=False)

    def unwrap_data(self, wrapped_data: bytes) -> bytes:
        """ Removes the Metadata (header + padding) from the data, and returns the original data.

        :param wrapped_data: The wrapped data, with length field and checksums and padding
        :return: The original not wrapped data
        """
        data_start = self.block_size * self._HEADER_BLOCKS
        data_len = self._header_parse_data_length(wrapped_data)

        added_length = self.block_size * self._HEADER_BLOCKS + self._get_pad_len(len(wrapped_data[:data_len]))
        if data_len != len(wrapped_data) - added_length:
            raise DataIntegrityError(f"Expected a data length of {data_len} bytes, got {len(wrapped_data)} bytes")
        return wrapped_data[data_start: data_start + data_len]


def checksum(data: bytes) -> bytes:
    sum_byte = 0
    for byte in data:
        sum_byte += byte
    return bytes([sum_byte % 2**8])


class DataIntegrityError(Exception):
    def __init__(self, message: str = "Data is corrupted"):
        super(DataIntegrityError, self).__init__(message)
