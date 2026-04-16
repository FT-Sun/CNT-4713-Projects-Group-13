import socket
import sys


from rsa_utils import (
    generate_rsa_keypair,
    export_public_key,
    import_public_key,
    rsa_encrypt,
    rsa_decrypt
)

from hash_utils import sha256_hash


def start_client():
    print("Starting client...")
    print("Creating RSA keypair")
    public_key, private_key = generate_rsa_keypair()
    print("RSA keypair created")
    return public_key, private_key



def send_connect_command(server_host, control_port):
    print("Creating client socket")
    control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to server")
    control_socket.connect((server_host, control_port))

    # send connect command
    control_socket.sendall(b"connect")

    # server responds with data port
    data_port_str = control_socket.recv(1024).decode().strip()
    data_port = int(data_port_str)

    print("Creating data socket")
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.connect((server_host, data_port))

    return control_socket, data_socket

def rsa_encrypt(message_bytes, public_key):
    # Encrypt the data using the Public Key
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
    
def rsa_decrypt(ciphertext, private_key):
    # Decrypt the data using the Private Key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def establish_tunnel(control_socket, data_socket, client_public_key):
    print("Requesting tunnel")

    # tell server tunnel is requested
    control_socket.sendall(b"tunnel")

    # send client public key on data socket
    client_pub_bytes = export_public_key(client_public_key)
    data_socket.sendall(client_pub_bytes)

    # receive server public key
    server_pub_bytes = data_socket.recv(4096)
    server_public_key = import_public_key(server_pub_bytes)

    print("Server public key received")
    print("Tunnel established")

    return server_public_key


def send_post(control_socket, data_socket, message, server_public_key):
    print(f"Encrypting message: {message}")

    encrypted_message = rsa_encrypt(message.encode(), server_public_key)
    print("Sending encrypted message:", encrypted_message.hex())

    # tell server post is requested
    control_socket.sendall(b"post")

    # send encrypted message
    data_socket.sendall(encrypted_message)

    return encrypted_message


def verify_server_response(data_socket, message, client_private_key):
    print("Received hash")
    encrypted_hash = data_socket.recv(4096)

    # decrypt returned hash using client private key
    returned_hash = rsa_decrypt(encrypted_hash, client_private_key).decode()

    print("Computing hash")
    local_hash = sha256_hash(message)

    if returned_hash == local_hash:
        print("Secure")
    else:
        print("Compromised")

def main():
    if len(sys.argv) != 3:
        print("Usage: python client_fabio.py server-host control-port")
        return

    server_host = sys.argv[1]
    control_port = int(sys.argv[2])

    # message required by project output example
    message = "Hello"

    # startup
    client_public_key, client_private_key = start_client()

    # connect command
    control_socket, data_socket = send_connect_command(server_host, control_port)

    # tunnel command
    server_public_key = establish_tunnel(control_socket, data_socket, client_public_key)

    # post command
    send_post(control_socket, data_socket, message, server_public_key)

    # verify server reply
    verify_server_response(data_socket, message, client_private_key)

    # cleanup
    control_socket.close()
    data_socket.close()


if __name__ == "__main__":
    main()
