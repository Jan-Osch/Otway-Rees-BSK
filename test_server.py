import unittest

from Server import Server, ServerWorker
from Utils import decrypt, encrypt


class ServerTest(unittest.TestCase):
    def test_get_new_worker_returns_correct_worker(self):
        server = Server(server_id='123', server_key='kk', max_connections=2, trusted_server=None, invoke_workers=False)
        output = server.get_new_worker()
        self.assertTrue(isinstance(output, ServerWorker))


class ServerWorkerTest(unittest.TestCase):
    def setUp(self):
        self.server_id = '123124'
        self.worker = ServerWorker(server_id=self.server_id, server_key=35, trusted_server=None)

    def test_connect_parses_the_message(self):
        self.worker.process_message_from_client_and_generate_message_to_trusted(['random', 'client_id', 'server_id', 'nested'])
        self.assertEqual(self.worker.client_random_value, 'random')
        self.assertEqual(self.worker.client_client_id, 'client_id')
        self.assertEqual(self.worker.client_server_id, 'server_id')

    def test_connect_from_client_for_valid_input_outputs_a_5_element_output(self):
        output = self.worker.process_message_from_client_and_generate_message_to_trusted(('random', 'client_id', self.server_id, 'nested'))
        self.assertNotEqual(output, self.worker.error_signal)
        self.assertEqual(len(output), 5)

    def test_connect_outputs_error_signal_if_server_id_does_not_match(self):
        output = self.worker.process_message_from_client_and_generate_message_to_trusted(('random', 'client_id', 'wrong_id', 'nested'))
        self.assertEqual(output, self.worker.error_signal)

    def test_connect_from_client_for_valid_input_5th_section_can_be_decrypted_using_server_key_to_4_element_array(self):
        server_key = 563
        self.worker = ServerWorker(server_id='server_id_123', server_key=server_key, trusted_server=None)
        encrypted = self.worker.process_message_from_client_and_generate_message_to_trusted(('random', 'client_id', 'server_id_123', 'nested'))
        self.assertNotEqual(encrypted, self.worker.error_signal)
        decrypted = decrypt(encrypted[4], server_key).split(':')
        self.assertEqual(len(decrypted), 4)

    def test_connect_from_client_for_valid_input_5th_section_contains_server_id_client_id_nonce_and_message(self):
        server_key = 563
        self.worker = ServerWorker(server_id='server_id_123', server_key=server_key, trusted_server=None)
        encrypted = self.worker.process_message_from_client_and_generate_message_to_trusted(('random', 'client_id', 'server_id_123', 'nested'))
        self.assertNotEqual(encrypted, self.worker.error_signal)
        decrypted = decrypt(encrypted[4], server_key).split(':')
        self.assertEqual(decrypted[1], 'random')
        self.assertEqual(decrypted[2], 'client_id')
        self.assertEqual(decrypted[3], 'server_id_123')

    def test_connect_from_trusted_server_unpacks_message_from_trusted(self):
        server_key = 178
        self.worker = ServerWorker(server_id='server_id_123', server_key=server_key, trusted_server=None)
        nested = encrypt('{0}:{1}'.format('server_nonce', 'session_key'), server_key)
        self.worker.nonce = 'server_nonce'
        self.worker.process_message_from_trusted_and_generate_response_for_client(('random_message', 'encrypted_client_message', nested))
        self.assertEqual(self.worker.session_key, 'session_key')
        self.assertEqual(self.worker.trusted_nonce, 'server_nonce')

    def test_if_nonce_does_not_match_returns_error_signal(self):
        server_key = 178
        self.worker = ServerWorker(server_id='server_id_123', server_key=server_key, trusted_server=None)
        nested = encrypt('{0}:{1}'.format('wrong_nonce', 'session_key'), server_key)
        self.worker.nonce = 'server_nonce'
        output = self.worker.process_message_from_trusted_and_generate_response_for_client(('random_message', 'encrypted_client_message', nested))
        self.assertEqual(output, self.worker.error_signal)

    def test_connect_from_trusted_returns_one_element_shorter_tuple_on_correct_data(self):
        server_key = 178
        self.worker = ServerWorker(server_id='server_id_123', server_key=server_key, trusted_server=None)
        nested = encrypt('{0}:{1}'.format('server_nonce', 'session_key'), server_key)
        self.worker.nonce = 'server_nonce'
        self.worker.client_random_value = 'random_message'
        output = self.worker.process_message_from_trusted_and_generate_response_for_client(('random_message', 'encrypted_client_message', nested))
        self.assertEqual(isinstance(output, tuple), True)
        self.assertEqual(len(output), 2)


if __name__ == '__main__':
    unittest.main()
