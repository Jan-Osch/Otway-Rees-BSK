from Queue import Queue
from threading import Thread

from Utils import prepare_inner_message, generate_random_key, decrypt


class AbstractEntity(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.hello_signal = 'HELLO'
        self.error_signal = 'ERROR'

    def establish_connection(self, endpoint):
        endpoint.input_queue.put(self.hello_signal)
        return endpoint.output_queue.get()

    def is_message_error(self, message):
        return self.error_signal == message

    @staticmethod
    def validate_message_length(message, intended):
        if len(message) != intended:
            raise IndexError
        if isinstance(message, str):
            raise IndexError
        for element in message:
            if element is '' or element is False or element is None:
                raise InvalidMessage


class AbstractQueueEntity(AbstractEntity):
    def __init__(self):
        AbstractEntity.__init__(self)
        self.input_queue = Queue()
        self.output_queue = Queue()


class AbstractStoppableEntity(AbstractQueueEntity):
    def __init__(self):
        AbstractQueueEntity.__init__(self)
        self.finish_signal = 'FINISH'
        self.waiting_queues = []

    def finish(self):
        for waiting_queue in self.waiting_queues:
            waiting_queue.put(self.finish_signal)

    def is_finish_signal(self, message):
        return message == self.finish_signal

    def get_from_queue(self, queue):
        self.waiting_queues.append(queue)
        return queue.get()


class AbstractServer(AbstractStoppableEntity):
    def __init__(self, max_connections, invoke_workers):
        AbstractStoppableEntity.__init__(self)
        self.max_connections = max_connections
        self.invoke_workers = invoke_workers
        self.workers = Queue(maxsize=max_connections)
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            message = self.get_from_queue(self.input_queue)
            if self.is_finish_signal(message):
                self.running = False
            else:
                self.output_queue.put(self.connect())

    def connect(self):
        worker = self.get_new_worker()
        self.workers.put(worker)
        self.start_worker(worker)
        return worker.input_queue, worker.output_queue

    def create_worker(self):
        return self.get_new_worker()

    def get_new_worker(self):
        raise NotImplementedError

    def start_worker(self, worker):
        if self.invoke_workers:
            worker.start()

    def finish_worker(self):
        self.workers.get()


class Server(AbstractServer):
    def __init__(self, server_id, server_key, max_connections, trusted_server, invoke_workers=True):
        AbstractServer.__init__(self, max_connections, invoke_workers)
        self.server_id = server_id
        self.server_key = server_key
        self.trusted_server = trusted_server

    def get_new_worker(self):
        return ServerWorker(self.server_id, self.server_key, self.trusted_server, self)


class ServerWorker(AbstractQueueEntity):
    def __init__(self, server_id, server_key, trusted_server, parent_server=None):
        AbstractQueueEntity.__init__(self)
        self.server_key = server_key
        self.server_id = server_id
        self.trusted_server = trusted_server
        self.trusted_server_input_queue = None
        self.trusted_server_output_queue = None
        self.trusted_random_value = None
        self.client_random_value = None
        self.client_client_id = None
        self.client_server_id = None
        self.trusted_nonce = None
        self.session_key = None
        self.nonce = None
        self.parent_server = parent_server

    def run(self):
        message_from_client = self.input_queue.get()
        message_to_trusted = \
            self.process_message_from_client_and_generate_message_to_trusted(message_from_client)
        if self.is_message_error(message_to_trusted):
            self.output_queue.put(self.error_signal)
        else:
            self.connect_to_trusted()
            self.trusted_server_input_queue.put(message_to_trusted)
            message_from_trusted = self.trusted_server_output_queue.get()
            message_for_client = self.create_response_for_client_from_message_from_trusted(message_from_trusted)
            self.output_queue.put(message_for_client)
        self.signal_parent()

    def process_message_from_client_and_generate_message_to_trusted(self, message):
        try:
            self.unpack_message_from_client(message)
            self.validate_server_id_match()
        except (IndexError, InvalidMessage, ValueError):
            return self.error_signal
        return self.prepare_message_for_trusted_server(message)

    def unpack_message_from_client(self, message):
        self.validate_message_length(message, 4)
        self.client_random_value = int(message[0])
        self.client_client_id = message[1]
        self.client_server_id = message[2]

    def validate_server_id_match(self):
        if self.client_server_id != self.server_id:
            raise InvalidMessage

    def prepare_message_for_trusted_server(self, message):
        return message + (self.prepare_nested_message_for_trusted(),)

    def prepare_nested_message_for_trusted(self):
        self.nonce = str(generate_random_key())
        return prepare_inner_message(self.server_key,
                                     self.nonce,
                                     self.client_random_value,
                                     self.client_client_id,
                                     self.client_server_id)

    def create_response_for_client_from_message_from_trusted(self, message):
        try:
            self.unpack_message_from_trusted(message)
            self.validate_random_value_from_trusted()
            self.validate_nested_message_from_trusted()
        except(IndexError, InvalidMessage, ValueError):
            return self.error_signal
        return message[:-1]

    def unpack_message_from_trusted(self, message):
        self.validate_message_length(message, 3)
        self.trusted_random_value = int(message[0])
        self.unpack_nested_message_from_trusted(message[2])

    def unpack_nested_message_from_trusted(self, encrypted_message):
        decrypted = decrypt(encrypted_message, self.server_key).split(':')
        self.validate_message_length(decrypted, 2)
        self.trusted_nonce, self.session_key = decrypted

    def validate_nested_message_from_trusted(self):
        if self.trusted_nonce != self.nonce:
            raise InvalidMessage

    def connect_to_trusted(self):
        self.trusted_server_input_queue, self.trusted_server_output_queue = \
            self.establish_connection(self.trusted_server)

    def validate_random_value_from_trusted(self):
        if self.trusted_random_value != self.client_random_value:
            raise InvalidMessage

    def signal_parent(self):
        if self.parent_server:
            self.parent_server.finish_worker()


class InvalidMessage(Exception):
    def __init__(self):
        Exception.__init__(self)
