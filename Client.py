from Server import AbstractEntity, InvalidMessage
from Utils import generate_random_key, prepare_inner_message, decrypt


class Client(AbstractEntity):
    def __init__(self, client_id=None, client_key=None, server=None, server_id=None):
        AbstractEntity.__init__(self)
        self.ok_signal = 'OK'
        self.client_id = client_id
        self.client_key = client_key
        self.server = server
        self.server_id = server_id
        self.server_worker_input = None
        self.server_worker_output = None
        self.random_value = None
        self.nonce = None
        self.server_random_value = None
        self.session_key = None
        self.trusted_nonce = None

    def run(self):
        self.server_worker_input, self.server_worker_output = self.establish_connection(self.server)
        self.server_worker_input.put(self.prepare_message_for_server())
        message_from_server = self.server_worker_output.get()
        response = self.process_message_from_server(message_from_server)
        self.evaluate_response(response)

    def prepare_message_for_server(self):
        self.generate_and_save_random_value()
        self.generate_and_save_nonce()
        return self.random_value, \
               self.client_id, \
               self.server_id, \
               self.generate_nested_message_for_trusted()

    def generate_and_save_random_value(self):
        self.random_value = generate_random_key()

    def generate_nested_message_for_trusted(self):
        return prepare_inner_message(self.client_key,
                                     self.nonce,
                                     self.random_value,
                                     self.client_id,
                                     self.server_id)

    def generate_and_save_nonce(self):
        self.nonce = str(generate_random_key())

    def process_message_from_server(self, message_from_server):
        try:
            self.unpack_message_from_server(message_from_server)
            self.unpack_nested_message_from_trusted(message_from_server[1])
            self.validate_nonce_from_trusted_server_matches()
            self.validate_random_value()
        except(IndexError, InvalidMessage, ValueError):
            return self.error_signal
        return self.ok_signal

    def unpack_nested_message_from_trusted(self, encrypted_message):
        decrypted = decrypt(encrypted_message, self.client_key).split(':')
        self.validate_message_length(decrypted, 2)
        self.trusted_nonce = decrypted[0]
        self.session_key = decrypted[1]

    def validate_nonce_from_trusted_server_matches(self):
        if self.trusted_nonce != self.nonce:
            raise InvalidMessage

    def evaluate_response(self, response):
        if response == self.error_signal:
            self.print_error_message()
        elif response == self.ok_signal:
            self.print_ok_response()

    def print_error_message(self):
        print self.error_signal

    def print_ok_response(self):
        print self.ok_signal

    def unpack_message_from_server(self, message_from_server):
        self.validate_message_length(message_from_server, 2)
        self.server_random_value = int(message_from_server[0])
        self.unpack_nested_message_from_trusted(message_from_server[1])

    def validate_random_value(self):
        if self.random_value != self.server_random_value:
            raise InvalidMessage
