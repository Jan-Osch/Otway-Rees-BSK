import random


def generate_random_key():
    return random.randint(0, 100000)


def decrypt(message, key):
    return ''.join([decrypt_character(char, key) for char in message])


def decrypt_character(char, key):
    return chr((ord(char) - key + 256) % 256)


def encrypt(message, key):
    return ''.join([encode_character(char, key) for char in message])


def encode_character(char, key):
    return chr((ord(char) + key) % 256)


def prepare_inner_message(encryption_key, nonce, random_value, client_id, server_id):
    return encrypt('{0}:{1}:{2}:{3}'.format(nonce, random_value, client_id, server_id), encryption_key)
