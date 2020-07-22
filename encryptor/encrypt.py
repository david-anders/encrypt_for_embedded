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

DATA_IV_PREFIX = b"IV:"
DATA_IV_CRYPT_SEP = b"\n"
IV_LEN = 128 // 8


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
    def encrypt_data(cls: Type[T], data: bytes, key: bytes) -> T:
        """ Encrypt data that you want to keep a secret.


        :param data: The Data (secret) that should be encrypted.
        :param key: The key to use to encrypt the data.
        :return: A new EncryptedData object.
        """
        iv = os.urandom(IV_LEN)  # Initialization Vector with Windows CryptGenRandom()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        enc_data = encryptor.update(data) + encryptor.finalize()
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

    @classmethod
    def deserialize(cls: Type[T], data: bytes) -> T:
        """ Deserialize An EncryptedData object.
        Can be used to read a shared secret.

        :param data: The serialized data representing the EncryptedData object.
        :return: A EncryptedData object.
        """
        assert data.startswith(DATA_IV_PREFIX)
        pref_len = len(DATA_IV_PREFIX)
        iv = data[pref_len: pref_len + IV_LEN]
        data_start = pref_len + IV_LEN + len(DATA_IV_CRYPT_SEP)
        assert data[pref_len + IV_LEN:data_start] == DATA_IV_CRYPT_SEP
        data = data[data_start:]
        return cls(data=data, iv=iv)

    def to_file(self, path_out: str):
        """ Write the EncryptedData object to a file for sharing.
        Writes the serialized EncryptedData to a file.
        This file can be safely used for sharing.
        :param path_out: The path to the file into which to write the serialized EncryptedData object.
        """
        with open(path_out, "wb") as file:
            file.write(self.serialize())

    def serialize(self) -> bytes:
        """ Serializes the EncryptedData object to a series of bytes, that can be easily used to share a secret.
        The other end can easily deserialize the object and with the correct key, encrypt and read the secret.
        :return: A bytes representation of the encrypted secret.
        """
        return DATA_IV_PREFIX + self.iv + b"\n" + self.data

    def decrypt(self, key) -> bytes:
        """ Decrypt this EncryptedData object.
        Decrypt the Data with the ocrrect key to read the secret.
        :param key: The key to decrypt the data with.
        :return: The decrypted secret.
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(self.data) + decryptor.finalize()


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
