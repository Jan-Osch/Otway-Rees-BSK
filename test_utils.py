import unittest

from Utils import generate_random_key, encrypt, decrypt


class GenerateRandomKeyTest(unittest.TestCase):
    def test_generated_key_is_not_none(self):
        generated_key = generate_random_key()
        self.assertIsNotNone(generated_key)

    def test_each_time_is_different(self):
        first_key = generate_random_key()
        second_key = generate_random_key()
        self.assertNotEqual(first_key, second_key)


class EncryptTest(unittest.TestCase):
    def test_produces_an_encrypted_message(self):
        encrypted_message = encrypt('message text', 123)
        self.assertIsNotNone(encrypted_message)

    def test_encrypted_message_is_different_than_original(self):
        original_message = 'message text'
        encrypted_message = encrypt(original_message, 123)
        self.assertNotEqual(original_message, encrypted_message)

    def test_encrypted_message_is_different_for_different_keys(self):
        original_message = 'message text'
        encrypted_first = encrypt(original_message, 123)
        encrypted_second = encrypt(original_message, 321)
        self.assertNotEqual(encrypted_first, encrypted_second)


class DecryptTest(unittest.TestCase):
    def test_produces_a_decrypted_message(self):
        decrypted_message = decrypt('encrypted', 123)
        self.assertIsNotNone(decrypted_message)

    def test_decrypted_message_is_different_for_different_keys(self):
        encrypted = 'encrypted'
        decrypted_first = decrypt(encrypted, 123)
        decrypted_second = decrypt(encrypted, 321)
        self.assertNotEqual(decrypted_first, decrypted_second)


class DecryptEncryptGenerateRandomKeyTest(unittest.TestCase):
    def test_encrypted_message_can_be_encrypted(self):
        original_message = 'original message'
        key = generate_random_key()
        encrypted_message = encrypt(original_message, key)
        decrypted_message = decrypt(encrypted_message, key)
        self.assertEquals(original_message, decrypted_message)


if __name__ == '__main__':
    unittest.main()
