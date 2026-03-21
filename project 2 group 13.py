import random
import socket
import sys


def build_dns_query(domain_name):
    query = bytearray(b"")

    ##########
    # HEADER #
    ##########
    transaction_id = random.randint(0, 0xFFFF)
    query += transaction_id.to_bytes(2, 'big')

    # A query packet without any special options will have its flags field simply be set to 0
    flags = (0).to_bytes(2, 'big')
    query += flags

    num_questions = (1).to_bytes(2, 'big')
    query += num_questions

    num_answers = (0).to_bytes(2, 'big')
    query += num_answers

    num_authority_rrs = (0).to_bytes(2, 'big')
    query += num_authority_rrs

    num_additional_rrs = (0).to_bytes(2, 'big')
    query += num_additional_rrs

    ############
    # QUESTION #
    ############
    # Encode the domain_name into bytes
    encoded_domain_name = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded_domain_name += bytes([len(part)]) + part
    encoded_domain_name += b"\x00"

    qname = encoded_domain_name
    query.extend(qname)

    # QTYPE (1 = A record)
    qtype = (1).to_bytes(2, 'big')
    query += qtype

    # QCLASS (1 = IN [the internet])
    qclass = (1).to_bytes(2, 'big')
    query += qclass

    return query, transaction_id


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
