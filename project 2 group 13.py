import socket
import sys


def send_dns_query(domain_name, root_server_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    # Below this is where the Query builder code should be (make sure to delete this once implemented)
    # Example:
    # dns_query = build_dns_query(domain_name)
    dns_query = b""  # TODO: replace with real DNS query

    server_address = (root_server_ip, 53)

    try:
        print(f"Sending DNS query to {root_server_ip} ...")
        sock.sendto(dns_query, server_address)

        # This is where the reply should be read from the Response Parser, delete once implemented

    except socket.timeout:
        print("DNS server did not respond (timeout).")
        return None

    finally:
        sock.close()


if __name__ == "__main__":
    # Main loop implementation to be done, remove this once finished.
    pass