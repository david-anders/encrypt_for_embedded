import os
import unittest
from difflib import SequenceMatcher
from math import floor, ceil

from encryptor.encrypt import EncryptedData, _Metadata, DataIntegrityError


class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.test_data = os.urandom(1024)
        self.test_key = os.urandom(128 // 8)
        self.test_iv = os.urandom(128 // 8)

    def test_encryption_and_decryption_dont_change_data(self):
        encrypted_data = EncryptedData.encrypt_data(self.test_data, self.test_key)
        decrypted_data = encrypted_data.decrypt(self.test_key)
        self.assertEqual(self.test_data, decrypted_data)

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
        os.remove("enc_test_temp_file")
        self.assertEqual(written_data, read_data)


class TestPadder(unittest.TestCase):
    def test_long_padding_is_filling_until_aligned(self):
        pad_len = 16
        test_data = b"\xFF" * (pad_len + 1)
        self.assertEqual(len(_Metadata(pad_len).wrap_data(test_data)) % pad_len, 0)

    def test_short_padding_is_adding_a_new_segment(self):
        pad_len = 16
        test_data = b"\xFF" * (pad_len - 1)
        self.assertEqual(len(_Metadata(pad_len).wrap_data(test_data)) % pad_len, 0)

    def test_data_corruption_raises_exception(self):
        pad_len = 16
        data_len = (pad_len * 250)
        padded_data = _Metadata(pad_len).wrap_data(b"\xFF" * data_len)
        corrupted_data = padded_data[:data_len] + padded_data[data_len + 1:]
        self.assertRaises(DataIntegrityError, _Metadata(pad_len).unwrap_data, corrupted_data)

    def test_padding_length_is_calculated_correctly(self):
        pad_len = 16
        padder = _Metadata(pad_len)
        self.assertEqual(padder._get_pad_len(pad_len), 0)
        self.assertEqual(padder._get_pad_len(pad_len - 1), 1)

    def test_add_padding_and_remove_padding_are_opposite_operations(self):
        byte = b'1'
        pad_len = 16
        padder = _Metadata(pad_len)
        test_data = [byte * data_length for data_length in range(512)]
        for test in test_data:
            with self.subTest(data_len=len(test)):
                padded_data = padder.wrap_data(test)
                unpadded_data = padder.unwrap_data(padded_data)
                self.assertEqual(test, unpadded_data)


if __name__ == '__main__':
    unittest.main()
