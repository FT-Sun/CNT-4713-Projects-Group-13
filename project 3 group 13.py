import socket
import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def sha256_hash(message):
    hash_object = hashlib.sha256(message.encode("utf-8"))
    return hash_object.hexdigest()


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key


def export_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def import_public_key(pub_bytes):
    return serialization.load_pem_public_key(pub_bytes)


def rsa_encrypt(message_bytes, public_key):
    return public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


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

    control_socket.sendall(b"connect")

    data_port_str = control_socket.recv(1024).decode().strip()
    data_port = int(data_port_str)

    print("Creating data socket")
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.connect((server_host, data_port))

    return control_socket, data_socket


def establish_tunnel(control_socket, data_socket, client_public_key):
    print("Requesting tunnel")

    control_socket.sendall(b"tunnel")

    client_pub_bytes = export_public_key(client_public_key)
    data_socket.sendall(client_pub_bytes)

    server_pub_bytes = data_socket.recv(4096)
    server_public_key = import_public_key(server_pub_bytes)

    print("Server public key received")
    print("Tunnel established")

    return server_public_key


def send_post(control_socket, data_socket, message, server_public_key):
    print(f"Encrypting message: {message}")

    encrypted_message = rsa_encrypt(message.encode(), server_public_key)
    print("Sending encrypted message:", encrypted_message.hex())

    control_socket.sendall(b"post")

    data_socket.sendall(encrypted_message)

    return encrypted_message


def verify_server_response(data_socket, message, client_private_key):
    print("Received hash")
    encrypted_hash = data_socket.recv(4096)

    returned_hash = rsa_decrypt(encrypted_hash, client_private_key).decode()

    print("Computing hash")
    local_hash = sha256_hash(message)

    if returned_hash == local_hash:
        print("Secure")
    else:
        print("Compromised")


def main_client():
    if len(sys.argv) != 4:
        print("Usage: python project3_group13.py client server-host control-port")
        return

    server_host = sys.argv[2]
    control_port = int(sys.argv[3])

    message = "Hello"

    client_public_key, client_private_key = start_client()

    control_socket, data_socket = send_connect_command(server_host, control_port)

    server_public_key = establish_tunnel(control_socket, data_socket, client_public_key)

    send_post(control_socket, data_socket, message, server_public_key)

    verify_server_response(data_socket, message, client_private_key)

    control_socket.close()
    data_socket.close()


def handle_client(control_conn, server_public, server_private):
    print("Awaiting commands from client...")

    data_socket = None
    data_conn = None
    client_public_key = None

    while True:
        cmd = control_conn.recv(1024)
        if not cmd:
            break

        cmd = cmd.decode().strip()

        if cmd == "connect":
            print("Connection requested. Creating data socket")

            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.bind(("", 0))
            data_socket.listen(1)

            data_port = data_socket.getsockname()[1]
            control_conn.sendall(str(data_port).encode())

            data_conn, _ = data_socket.accept()

        elif cmd == "tunnel":
            print("Tunnel requested. Sending public key")

            client_pub_bytes = data_conn.recv(4096)
            client_public_key = import_public_key(client_pub_bytes)

            server_pub_bytes = export_public_key(server_public)
            data_conn.sendall(server_pub_bytes)

        elif cmd == "post":
            print("Post requested.")

            encrypted_message = data_conn.recv(8192)
            print("Received encrypted message:", encrypted_message.hex())

            decrypted_message = rsa_decrypt(encrypted_message, server_private).decode()
            print("Decrypted message:", decrypted_message)

            print("Computing hash")
            msg_hash = sha256_hash(decrypted_message)

            encrypted_hash = rsa_encrypt(msg_hash.encode(), client_public_key)
            print("Responding with hash:", encrypted_hash.hex())

            data_conn.sendall(encrypted_hash)
            break

    if data_conn:
        data_conn.close()
    if data_socket:
        data_socket.close()
    control_conn.close()


def main_server():
    if len(sys.argv) != 3:
        print("Usage: python project3_group13.py server control-port")
        return

    control_port = int(sys.argv[2])

    print("Starting server...")
    print("Creating RSA keypair")
    server_public, server_private = generate_rsa_keypair()
    print("RSA keypair created")

    print("Creating server socket")
    control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control_socket.bind(("", control_port))
    control_socket.listen(5)

    print("Awaiting connections...")

    while True:
        conn, addr = control_socket.accept()
        handle_client(conn, server_public, server_private)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server: python project3_group13.py server 8080")
        print("  Client: python project3_group13.py client localhost 8080")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "server":
        main_server()
    elif mode == "client":
        main_client()
    else:
        print("Invalid mode. Use 'server' or 'client'.")
