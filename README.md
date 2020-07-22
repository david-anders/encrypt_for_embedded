# encrypt_for_embedded
Repo for Distributing data safely to embedded devices.

Data can be encrypted or decrypted on a PC using a Python module, which supplies an easy interface for encrypting and decrypting data safely using AES with a 128 bit Key length in CBC Mode.
An IV is automatically generated using os.urandom which in Windows uses CryptGenRandom().
The IV is supplied along with the encrypted data in plaintext.

The C module (WIP) can be used decrypt the data on a microcontroller.
