from Server import AbstractEntity
from Utils import generate_random_key, prepare_inner_message, decrypt


class Client(AbstractEntity):
    def __init__(self, client_id=None, client_key=None, server=None, server_id=None):
        AbstractEntity.__init__(self)
        self.ok_signal = 'OK'
        self.client_id = client_id
        self.client_key = client_key
        self.server = server
        self.server_id = server_id
        self.random_value = None
        self.nonce = None
        self.server_random_value = None
        self.session_key = None
        self.server_nonce = None

    def run(self):
        self.server.input_queue.put(self.prepare_message_for_server())
        message_from_server = self.input_queue.get()
        response = self.connect_from_server(message_from_server)
        self.evaluate_response(response)

    def prepare_message_for_server(self):
        self.generate_and_save_random_value()
        self.generate_and_save_nonce()
        return self.random_value, self.client_id, self.server_id, self.generate_nested_message_for_server()

    def generate_and_save_random_value(self):
        self.random_value = str(generate_random_key())

    def generate_nested_message_for_server(self):
        return prepare_inner_message(self.client_key, self.nonce, self.random_value, self.client_id, self.server_id)

    def generate_and_save_nonce(self):
        self.nonce = str(generate_random_key())

    def connect_from_server(self, message_from_server):
        self.server_random_value = message_from_server[0]
        try:
            self.decrypt_nested_message(message_from_server[1])
        except IndexError:
            return self.error_signal
        if not self.nested_message_is_valid():
            return self.error_signal
        return self.ok_signal

    def decrypt_nested_message(self, encrypted_message):
        decrypted = decrypt(encrypted_message, self.client_key).split(':')
        self.server_nonce = decrypted[0]
        self.session_key = decrypted[1]

    def nested_message_is_valid(self):
        return self.server_nonce == self.nonce

    def evaluate_response(self, response):
        if response == self.error_signal:
            self.print_error_message()
        elif response == self.ok_signal:
            self.print_ok_response()

    @staticmethod
    def print_error_message():
        print ('ERROR')

    @staticmethod
    def print_ok_response():
        print ('OK')
