import unittest
from Queue import Queue
from threading import Thread

from TrustedServer import TrustedServer, TrustedServerWorker
from Utils import encrypt, decrypt


class TrustedServerTest(unittest.TestCase):
    def setUp(self):
        self.trusted = TrustedServer(keys={}, max_connections=123, invoke_workers=False)

    def tearDown(self):
        if self.trusted.running:
            self.trusted.finish()
            self.trusted.join()

    def put_message_on_queue(self):
        self.trusted.input_queue.put('messsage')

    def start_multiple_connections(self, number):
        for _ in range(number):
            self.trusted.connect()

    def test_is_subclass_of_thread(self):
        self.assertTrue(isinstance(self.trusted, Thread))

    def test_has_field_input_queue_that_is_a_queue(self):
        self.assertTrue(isinstance(self.trusted.input_queue, Queue))

    def test_has_field_output_queue(self):
        self.assertTrue(isinstance(self.trusted.output_queue, Queue))

    def test_creates_a_tuple_with_two_queues_when_connection_is_started(self):
        self.trusted.start()
        self.trusted.input_queue.put('message')
        output = self.trusted.output_queue.get()
        self.assertTrue(isinstance(output, tuple))

    def put_multiple_messages_on_queue(self, number):
        for _ in range(number):
            self.put_message_on_queue()


class TrustedServerWorkerTestCase(unittest.TestCase):
    def setUp(self):
        self.client_id = 'client_id'
        self.server_id = 'server_id'
        self.client_nonce = 'default_client_nonce'
        self.server_nonce = 'default_server_nonce'
        self.random_value = 471928
        self.server_key = 55
        self.client_key = 33

        self.worker = TrustedServerWorker(keys={self.client_id: self.client_key,
                                                self.server_id: self.server_key})

    def prepare_message(self, random_value, client_id, server_id, message_from_client, message_from_server):
        return random_value, client_id, server_id, message_from_client, message_from_server

    def prepare_inner_message(self, encryption_key, nonce, random_value, client_id, server_id):
        return encrypt('{0}:{1}:{2}:{3}'.format(nonce, random_value, client_id, server_id), encryption_key)

    def prepare_connect_message(self,
                                random_value=None,
                                client_id=None,
                                server_id=None,
                                client_key=None,
                                client_nonce=None,
                                client_random_value=None,
                                client_server_id=None,
                                client_client_id=None,
                                server_nonce=None,
                                server_key=None,
                                server_client_id=None,
                                server_server_id=None,
                                server_random_value=None):
        random_value = random_value or self.random_value
        client_id = client_id or self.client_id
        server_id = server_id or self.server_id
        client_key = client_key or self.client_key
        client_nonce = client_nonce or self.client_nonce
        client_random_value = client_random_value or random_value
        client_server_id = client_server_id or server_id
        client_client_id = client_client_id or client_id
        server_nonce = server_nonce or self.server_nonce

        server_key = server_key or self.server_key
        server_client_id = server_client_id or client_id
        server_server_id = server_server_id or server_id
        server_random_value = server_random_value or random_value

        message_from_client = self.prepare_inner_message(client_key,
                                                         client_nonce,
                                                         client_random_value,
                                                         client_client_id,
                                                         client_server_id)

        message_from_server = self.prepare_inner_message(server_key,
                                                         server_nonce,
                                                         server_random_value,
                                                         server_client_id,
                                                         server_server_id)

        return self.prepare_message(random_value, client_id, server_id, message_from_client, message_from_server)

    def decrypt_and_split(self, key, message):
        return decrypt(message, key).split(':')

    def test_first_segment_contains_correct_random_value(self):
        connect_message = self.prepare_connect_message(random_value=self.random_value)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message)
        self.assertEqual(output[0], self.random_value)

    def test_returns_error_signal_on_not_matching_random_value(self):
        random_val_one = 123
        random_val_two = 41242
        random_val_three = 41421
        connect_message = self.prepare_connect_message(random_value=random_val_one,
                                                       client_random_value=random_val_two,
                                                       server_random_value=random_val_three)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message)
        self.assertEqual(output, self.worker.error_signal)

    def test_returns_error_signal_when_message_is_too_long(self):
        random_val_one = 123
        random_val_two = 41242
        random_val_three = 41421
        connect_message = self.prepare_connect_message(random_value=random_val_one,
                                                       client_random_value=random_val_two,
                                                       server_random_value=random_val_three)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message + ('random',))
        self.assertEqual(output, self.worker.error_signal)

    def test_output_in_second_segment_contains_client_nonce(self):
        client_nonce = 'secret_client_nonce'
        connect_message = self.prepare_connect_message(client_nonce=client_nonce)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message)
        decrypted_second_segment = self.decrypt_and_split(self.client_key, output[1])
        self.assertEqual(client_nonce, decrypted_second_segment[0])

    def test_output_in_second_segment_contains_a_session_key_each_time_different(self):
        self.worker.keys['first'] = 12
        self.worker.keys['second'] = 23
        self.worker.keys['third'] = 44
        self.worker.keys['fourth'] = 66
        first_key = self.prepare_connect_message('1', 12, 'first')[1]
        second_key = self.prepare_connect_message('2', 23, 'second')[1]
        third_key = self.prepare_connect_message('3', 44, 'third')[1]
        fourth_key = self.prepare_connect_message('4', 66, 'fourth')[1]
        self.assertNotEqual(first_key, second_key)
        self.assertNotEqual(third_key, second_key)
        self.assertNotEqual(third_key, fourth_key)

    def test_third_segment_contains_server_nonce(self):
        nonce_from_server = 'secret_server_nonce'
        connect_message = self.prepare_connect_message(server_nonce=nonce_from_server)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message)
        decrypted_third_segment = self.decrypt_and_split(self.server_key, output[2])
        self.assertEqual(decrypted_third_segment[0], nonce_from_server)

    def test_returns_error_signal_on_not_matching_client_id(self):
        client_id_one = '1'
        client_id_two = '2'
        client_id_three = '3'
        self.worker = TrustedServerWorker({'1': self.client_key})
        connect_message = self.prepare_connect_message(client_id=client_id_one,
                                                       client_client_id=client_id_two,
                                                       server_client_id=client_id_three)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message)
        self.assertEqual(output, self.worker.error_signal)

    def test_returns_error_signal_on_not_matching_server_id(self):
        server_id_one = '1'
        server_id_two = '2'
        server_id_three = '3'
        self.worker = TrustedServerWorker({'1': self.server_key})
        connect_message = self.prepare_connect_message(server_id=server_id_one,
                                                       server_server_id=server_id_two,
                                                       client_server_id=server_id_three)
        output = self.worker.process_message_from_server_and_generate_answer(connect_message)
        self.assertEqual(output, self.worker.error_signal)


if __name__ == '__main__':
    unittest.main()
