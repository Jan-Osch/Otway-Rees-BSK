from Queue import Queue
from threading import Thread

from Utils import prepare_inner_message, generate_random_key, decrypt


class AbstractEntity(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.error_signal = 'ERROR'
        self.finish_signal = 'FINISH'
        self.input_queue = Queue()
        self.output_queue = Queue()

    def finish(self):
        self.input_queue.put(self.finish_signal)

    def is_finish_signal(self, message):
        return message == self.finish_signal

    def is_message_error(self, message):
        message == self.error_signal


class AbstractServer(AbstractEntity):
    def __init__(self, max_connections, invoke_workers):
        AbstractEntity.__init__(self)
        self.max_connections_signal = 'MAX_CONNECTIONS_REACHED'
        self.max_connections = max_connections
        self.number_of_workers = 0
        self.invoke_workers = invoke_workers
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            message = self.input_queue.get()
            if self.is_finish_signal(message):
                self.running = False
            else:
                self.output_queue.put(self.connect())

    def connect(self):
        if self.can_create_connection():
            worker = self.create_worker()
            self.start_worker(worker)
            return worker.input_queue, worker.output_queue
        return self.max_connections_signal

    def can_create_connection(self):
        return self.number_of_workers < self.max_connections

    def create_worker(self):
        self.number_of_workers += 1
        return self.get_new_worker()

    def is_finish_signal(self, message):
        return message == self.finish_signal

    def finish(self):
        self.input_queue.put(self.finish_signal)

    def get_new_worker(self):
        raise NotImplementedError

    def start_worker(self, worker):
        if self.invoke_workers:
            worker.start()


class Server(AbstractServer):
    def __init__(self, server_id, server_key, max_connections, trusted_server, invoke_workers=True):
        AbstractServer.__init__(self, max_connections, invoke_workers)
        self.server_id = server_id
        self.server_key = server_key
        self.trusted_server = trusted_server

    def get_new_worker(self):
        return ServerWorker(self.server_id, self.server_key, self.trusted_server)


class ServerWorker(AbstractEntity):
    def __init__(self, server_id, server_key, trusted_server):
        AbstractEntity.__init__(self)
        self.server_key = server_key
        self.server_id = server_id
        self.trusted_server = trusted_server
        self.main_random_message = None
        self.main_client_id = None
        self.main_server_id = None
        self.trusted_nonce = None
        self.session_key = None
        self.nonce = None

    def run(self):
        message_from_client = self.input_queue.get()
        if self.is_message_error(message_from_client):
            self.output_queue.put(self.error_signal)
            return
        message_to_trusted = self.connect_from_client(message_from_client)
        if self.is_message_error(message_to_trusted):
            self.output_queue.put(self.error_signal)
            return
        self.trusted_server.input_queue.put(message_to_trusted)
        message_from_trusted = self.input_queue.get()
        if self.is_message_error(message_from_client):
            self.output_queue.put(self.error_signal)
            return
        self.output_queue.put(self.connect_from_trusted(message_from_trusted))

    def connect_from_client(self, message):
        self.unpack_message_from_client(message)
        if not self.server_id_matches():
            return self.error_signal
        return self.prepare_message_for_trusted_server(message)

    def unpack_message_from_client(self, message):
        self.main_random_message = message[0]
        self.main_client_id = message[1]
        self.main_server_id = message[2]

    def server_id_matches(self):
        return self.main_server_id == self.server_id

    def prepare_message_for_trusted_server(self, message):
        partial = list(message)
        partial.append(self.prepare_nested_message_for_trusted())
        return tuple(partial)

    def prepare_nested_message_for_trusted(self):
        self.nonce = generate_random_key()
        return prepare_inner_message(self.server_key,
                                     self.nonce,
                                     self.main_random_message,
                                     self.main_client_id,
                                     self.main_server_id)

    def connect_from_trusted(self, message):
        self.unpack_message_from_trusted(message)
        if not self.nested_message_is_valid():
            return self.error_signal
        return self.prepare_response_to_client(message)

    def unpack_message_from_trusted(self, message):
        self.unpack_nested_message_from_trusted(message[2])

    def unpack_nested_message_from_trusted(self, encrypted_message):
        decrypted = decrypt(encrypted_message, self.server_key).split(':')
        self.trusted_nonce, self.session_key = decrypted

    def nested_message_is_valid(self):
        return self.trusted_nonce == self.nonce

    @staticmethod
    def prepare_response_to_client(message):
        return message[:-1]
