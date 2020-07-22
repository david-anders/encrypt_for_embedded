import os
import unittest
from difflib import SequenceMatcher

from encryptor.encrypt import EncryptedData


class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.test_data = os.urandom(1024)
        self.test_key = os.urandom(128 // 8)
        self.test_iv = os.urandom(128 // 8)

    def test_encryption_end_decryption_dont_change_data(self):
        encypted_data = EncryptedData.encrypt_data(self.test_data, self.test_key)
        decryted_data = encypted_data.decrypt(self.test_key)
        self.assertEqual(self.test_data, decryted_data)

    def test_serialize_and_deserialize_are_opposite_operations(self):
        s_data = EncryptedData(data=self.test_data, iv=self.test_iv).serialize()
        d_data = EncryptedData.deserialize(s_data)
        self.assertEqual(d_data.data, self.test_data)
        self.assertEqual(d_data.iv, self.test_iv)

    def test_consecutive_encryptions_yield_different_results(self):
        first_encrypt = EncryptedData.encrypt_data(self.test_data, self.test_key)
        second_encrypt = EncryptedData.encrypt_data(self.test_data, self.test_key)
        self.assertNotEqual(first_encrypt.iv, second_encrypt.iv)
        self.assertNotEqual(SequenceMatcher, second_encrypt.data)
        # check that they are also not almost equal:
        self.assertLess(SequenceMatcher(None, first_encrypt.data, second_encrypt.data).ratio(), 0.5)

    def test_file_write_and_file_read_are_producing_the_same_results(self):
        if os.path.isfile("enc_test_temp_file"):
            os.remove("enc_test_temp_file")
        written_data = EncryptedData(data=self.test_data, iv=self.test_iv)
        written_data.to_file("enc_test_temp_file")
        read_data = EncryptedData.from_file("enc_test_temp_file")
        self.assertEqual(written_data, read_data)
        os.remove("enc_test_temp_file")


if __name__ == '__main__':
    unittest.main()
