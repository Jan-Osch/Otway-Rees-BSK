from Client import Client
from Server import Server
from TrustedServer import TrustedServer
from Utils import generate_random_key

id_for_alice = 'alice'
id_for_bob = 'bob'
key_for_alice = generate_random_key()
key_for_bob = generate_random_key()
trusted_server = TrustedServer(keys={id_for_alice: key_for_alice, id_for_bob: key_for_bob}, max_connections=10)
trusted_server.start()
server = Server(server_id=id_for_bob, server_key=key_for_bob, max_connections=10, trusted_server=trusted_server)
server.start()
client = Client(client_id=id_for_alice, client_key=key_for_alice, server=server, server_id=id_for_bob)
client.start()
client.join()
server.finish()
trusted_server.finish()
