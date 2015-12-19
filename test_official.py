from Utils import generate_random_key
from TrustedServer import TrustedServer
from Server import Server
from Client import Client
from threading import active_count, enumerate, current_thread, Thread
import sys


id_for_alice = 'alice'
id_for_bob = 'bob'
key_for_alice = generate_random_key()
key_for_bob = generate_random_key()

trusted_server = TrustedServer(keys={id_for_alice: key_for_alice, id_for_bob: key_for_bob},max_connections=10)
trusted_server.start()

server = Server(server_id=id_for_bob, server_key=key_for_bob, max_connections=10, trusted_server=trusted_server)
server.start()

client = Client(client_id=id_for_alice, client_key=key_for_alice, server=server, server_id=id_for_bob)
client.start()

def clean():
	client.join(120)
	server.finish()
	trusted_server.finish()
	server.join(120)
	trusted_server.join(120)
t = Thread(target=clean)
t.start()
t.join(360)

if active_count() > 1:
	for t in enumerate():
		print t
		if t != current_thread():
			t._Thread__stop() 
	print 'Koniec'
	sys.exit(1)

