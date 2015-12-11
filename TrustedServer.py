from Server import AbstractServer, AbstractEntity
from Utils import decrypt, encrypt, generate_random_key


class TrustedServer(AbstractServer):
    def __init__(self, keys, max_connections, invoke_workers=True):
        AbstractServer.__init__(self, max_connections, invoke_workers)
        self.keys = keys

    def get_new_worker(self):
        return TrustedServerWorker(self.keys)


class TrustedServerWorker(AbstractEntity):
    def __init__(self, keys):
        AbstractEntity.__init__(self)
        self.keys = keys
        self.main_random_message = None
        self.main_client_id = None
        self.main_server_id = None
        self.client_random_message = None
        self.client_client_id = None
        self.client_server_id = None
        self.server_random_message = None
        self.server_client_id = None
        self.server_server_id = None
        self.client_nonce = None
        self.server_nonce = None
        self.client_key = None
        self.server_key = None
        self.running = False

    def run(self):
        self.running = True
        message = self.input_queue.get()
        if not self.is_finish_signal(message):
            self.output_queue.put(self.connect(message))
        self.running = False

    def connect(self, message):
        self.unpack_main_message(message)
        if not self.ids_are_valid([self.main_client_id, self.main_server_id]):
            return self.error_signal
        self.unpack_nested_messages(message)
        if not self.nested_messages_are_valid():
            return self.error_signal
        return self.generate_response()

    def generate_response(self):
        return (self.main_random_message,
                self.generate_nested_response_to_client(),
                self.generate_nested_response_to_server())

    def generate_nested_response_to_client(self):
        message = '{0}:{1}'.format(self.client_nonce, generate_random_key())
        return self.encrypt_with_id(message, self.main_client_id)

    def generate_nested_response_to_server(self):
        message = '{0}:{1}'.format(self.server_nonce, generate_random_key())
        return self.encrypt_with_id(message, self.main_server_id)

    def decrypt_with_id_and_split(self, message, id_key, separator):
        return decrypt(message, self.keys[id_key]).split(separator)

    def encrypt_with_id(self, message, id_key):
        return encrypt(message, self.keys[id_key])

    def unpack_main_message(self, message):
        self.main_random_message = message[0]
        self.main_client_id = message[1]
        self.main_server_id = message[2]

    def ids_are_valid(self, ids):
        return all([identifier in self.keys.keys() for identifier in ids])

    def unpack_nested_messages(self, message):
        self.unpack_client_nested_message(self.main_client_id, message[3])
        self.unpack_server_nested_message(self.main_server_id, message[4])

    def unpack_client_nested_message(self, client_id, message):
        decrypted_message = self.decrypt_with_id_and_split(message, client_id, ':')
        self.client_nonce = decrypted_message[0]
        self.client_random_message = decrypted_message[1]
        self.client_client_id = decrypted_message[2]
        self.client_server_id = decrypted_message[3]

    def unpack_server_nested_message(self, server_id, message):
        decrypted_message = self.decrypt_with_id_and_split(message, server_id, ':')
        self.server_nonce = decrypted_message[0]
        self.server_random_message = decrypted_message[1]
        self.server_client_id = decrypted_message[2]
        self.server_server_id = decrypted_message[3]

    def nested_messages_are_valid(self):
        return self.client_id_matches() and self.server_id_matches() and self.random_message_matches()

    def client_id_matches(self):
        return self.main_client_id == self.server_client_id == self.client_client_id

    def server_id_matches(self):
        return self.main_server_id == self.server_server_id == self.client_server_id

    def random_message_matches(self):
        return self.main_random_message == self.client_random_message == self.server_random_message
