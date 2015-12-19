import unittest
from Queue import Queue

from mock import MagicMock

from Client import Client
from Server import AbstractQueueEntity
from Utils import decrypt, encrypt


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.client_key = 1231241
        self.client_id = 'client_id_element'
        self.client = Client(client_id=None, client_key=self.client_key, server=None, server_id=None)

    def test_connect_produces_a_3_element_tuple_for_server(self):
        output = self.client.prepare_message_for_server()
        self.assertEqual(len(output), 4)
        self.assertTrue(isinstance(output, tuple))

    def test_connect_generates_random_message_and_saves_it_and_sends_it_as_first_element(self):
        output = self.client.prepare_message_for_server()
        random_value = self.client.random_value
        self.assertEqual(output[0], random_value)

    def test_connect_sends_client_id_as_second_element(self):
        client = Client(client_id=self.client_id, client_key=self.client_key, server=None, server_id=None)
        output = client.prepare_message_for_server()
        self.assertEqual(output[1], self.client_id)

    def test_connect_sends_server_id_as_third_element(self):
        server_id = 'secret_server_id'
        client = Client(client_id=None, client_key=123, server=None, server_id=server_id)
        output = client.prepare_message_for_server()
        self.assertEqual(output[2], server_id)

    def test_connect_sends_encrypted_with_own_key_element_that_contains_4_elements_separated_by_colons(self):
        encrypted = self.client.prepare_message_for_server()[3]
        decrypted = decrypt(encrypted, self.client_key).split(':')
        self.assertEqual(len(decrypted), 4)

    def test_connect_sends_encrypted_own_nonce_at_first_position(self):
        encrypted = self.client.prepare_message_for_server()[3]
        nonce = self.client.nonce
        decrypted = decrypt(encrypted, self.client_key).split(':')
        self.assertEqual(decrypted[0], nonce)

    def test_connect_sends_encrypted_random_value_at_second_position(self):
        encrypted = self.client.prepare_message_for_server()[3]
        random = self.client.random_value
        decrypted = decrypt(encrypted, self.client_key).split(':')
        self.assertEqual(int(decrypted[1]), random)

    def test_connect_sends_encrypted_random_value_at_third_position(self):
        cid = 'client_id'
        client = Client(client_id=cid, client_key=self.client_key, server=None, server_id=None)
        encrypted = client.prepare_message_for_server()[3]
        decrypted = decrypt(encrypted, self.client_key).split(':')
        self.assertEqual(decrypted[2], '%s' % cid)

    def test_connect_sends_encrypted_random_server_id_at_last_position(self):
        sid = 'server_id'
        client = Client(client_id=None, client_key=self.client_key, server=None, server_id=sid)
        encrypted = client.prepare_message_for_server()[3]
        decrypted = decrypt(encrypted, self.client_key).split(':')
        self.assertEqual(decrypted[3], '%s' % sid)

    def test_connect_from_server_unpacks_message(self):
        random_value_from_server = 53082
        self.client.process_message_from_server(('%s' % random_value_from_server, 'anything'))
        self.assertEqual(self.client.server_random_value, random_value_from_server)

    def test_connect_from_server_unpacks_encrypted_message(self):
        random_value_from_server = 41280
        encrypted_message = encrypt('{0}:{1}'.format('nonce', 'session-key'), self.client_key)
        self.client.process_message_from_server((random_value_from_server, encrypted_message))
        self.assertEqual(self.client.trusted_nonce, 'nonce')
        self.assertEqual(self.client.session_key, 'session-key')

    def test_connect_from_server_if_encrypted_message_cannot_be_decrypted_to_two_elements_will_return_error_signal(
            self):
        client = Client(client_id=None, client_key=3197, server=None, server_id=None)
        random_value_from_server = 11
        encrypted_message = encrypt('{0}:{1}'.format('nonce', 'session-key'), self.client_key)
        response = client.process_message_from_server((random_value_from_server, encrypted_message))
        self.assertEqual(response, client.error_signal)

    def test_process_message_from_server_returns_error_when_nonce_does_not_match(self):
        random_value_from_server = 1231
        self.client.nonce = 'one-nonce'
        self.client.random_value = random_value_from_server
        encrypted_message = encrypt('{0}:{1}'.format('two-nonce', 'session-key'), self.client_key)
        response = self.client.process_message_from_server((random_value_from_server, encrypted_message))
        self.assertEqual(response, self.client.error_signal)

    def test_process_message_from_server_returns_error_when_random_message_does_not_match(self):
        random_value_from_server = 312789
        self.client.random_value = 41279412
        self.client.nonce = 'one-nonce'
        encrypted_message = encrypt('{0}:{1}'.format(self.client.nonce, 'session-key'), self.client_key)
        response = self.client.process_message_from_server((random_value_from_server, encrypted_message))
        self.assertEqual(response, self.client.error_signal)

    def test_connect_from_server_if_nested_message_matches_returns_own_ok_signal(self):
        random_value_from_server =  12312
        self.client.random_value = random_value_from_server
        generated_nonce = 'generated-nonce'
        self.client.nonce = generated_nonce
        encrypted_message = encrypt('{0}:{1}'.format('%s' % generated_nonce, 'session-key'), self.client_key)
        response = self.client.process_message_from_server((random_value_from_server, encrypted_message))
        self.assertEqual(response, self.client.ok_signal)


class ClientRunTests(unittest.TestCase):
    def setUp(self):
        self.client_key = 1231241
        self.client_id = 'client_id_element'
        self.mock_server = AbstractQueueEntity()
        self.mock_server.input_queue.put = MagicMock()
        self.mock_server_output_queue = Queue()
        self.mock_server_input_queue = Queue()
        self.client = Client(client_id=None, client_key=123, server=self.mock_server, server_id=None)
        self.client.prepare_message_for_server = MagicMock(return_value='mock_response')
        self.prepareQueues()
        self.client.establish_connection = MagicMock(
            return_value=(self.mock_server_input_queue, self.mock_server_output_queue))

    def prepareQueues(self):
        self.mock_server_output_queue.put(self.client.error_signal)

    def test_run_puts_on_server_input_queue_result_of_own_prepare_message_for_server(self):
        self.client.print_error_message = MagicMock()
        self.mock_server_output_queue.put('mock')
        self.client.run()
        self.assertTrue(self.client.prepare_message_for_server.called)
        self.assertFalse(self.mock_server_input_queue.empty())
        self.assertEqual(self.mock_server_input_queue.get(), 'mock_response')

    def test_run_when_gets_a_message_from_server_will_call_connect_from_server(self):
        self.mock_server_output_queue.get()
        self.mock_server_output_queue.put('mock_message_from_server')
        self.client.process_message_from_server = MagicMock()
        self.client.run()
        self.assertTrue(self.client.process_message_from_server.called)
        self.client.process_message_from_server.assert_called_with('mock_message_from_server')

    def test_run_when_gets_calls_print_ok_message_if_connect_from_server_returns_ok_message(self):
        self.client.print_ok_response = MagicMock()
        self.mock_server_output_queue.put('mock_message_from_server')
        self.client.process_message_from_server = MagicMock(return_value=self.client.ok_signal)
        self.client.run()
        self.assertTrue(self.client.print_ok_response.called)

    def test_run_when_gets_calls_print_error_message_if_connect_from_server_returns_error_signal(self):
        self.client.prepare_message_for_server = MagicMock(return_value='mock_response')
        self.client.print_error_message = MagicMock()
        self.mock_server_output_queue.put('mock_message_from_server')
        self.client.process_message_from_server = MagicMock(return_value=self.client.error_signal)
        self.client.run()
        self.assertTrue(self.client.print_error_message.called)


class ClientPrepareMessageForServerTest(unittest.TestCase):
    def setUp(self):
        self.client = Client(client_id='client_id', client_key=123, server='mockServer', server_id=None)

    def test_first_element_of_message_is_a_number(self):
        result = self.client.prepare_message_for_server()
        self.assertTrue(isinstance(result[0], int))


if __name__ == '__main__':
    unittest.main()
