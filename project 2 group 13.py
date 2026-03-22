import random
import socket
import sys
import struct


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

def parse_response(data):
    """
    Parses the DNS response bytes.
    Returns: (list of answers, list of authorities, list of additionals)
    Each list contains dictionaries with record data.
    """
    # 1. Parse Header (first 12 bytes)
    # ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
    header = struct.unpack("!HHHHHH", data[:12])
    ancount, nscount, arcount = header[3], header[4], header[5]
    
    offset = 12

    def parse_name(data, offset):
        """Helper to parse DNS names and handle compression pointers."""
        labels = []
        jumped = False
        initial_offset = offset
        
        while True:
            length = data[offset]
            # Check for compression (11000000 in binary = 0xc0)
            if (length & 0xC0) == 0xC0:
                pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
                if not jumped:
                    initial_offset = offset + 2
                offset = pointer
                jumped = True
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                labels.append(data[offset:offset+length].decode("ascii"))
                offset += length
        
        return ".".join(labels), (initial_offset if jumped else offset)

    # 2. Skip Question Section (We already know what we asked)
    # The server repeats the question, so we must advance the offset past it.
    _, offset = parse_name(data, offset)
    offset += 4  # Skip QTYPE and QCLASS

    def parse_records(count, data, current_offset):
        records = []
        for _ in range(count):
            name, current_offset = parse_name(data, current_offset)
            # Type (2), Class (2), TTL (4), Data Length (2)
            rtype, rclass, rttl, rdlength = struct.unpack("!HHIH", data[current_offset:current_offset+10])
            current_offset += 10
            
            rdata = data[current_offset:current_offset+rdlength]
            
            # If Type 1 (A Record), it's an IPv4 address
            if rtype == 1:
                ip = ".".join(map(str, rdata))
                records.append({"name": name, "type": "A", "value": ip})
            # If Type 2 (NS Record), it's a hostname for the next DNS server
            elif rtype == 2:
                ns_name, _ = parse_name(data, current_offset)
                records.append({"name": name, "type": "NS", "value": ns_name})
            else:
                records.append({"name": name, "type": rtype, "value": "other"})
                
            current_offset += rdlength
        return records, current_offset

    # 3. Parse Sections
    answers, offset = parse_records(ancount, data, offset)
    authorities, offset = parse_records(nscount, data, offset)
    additionals, offset = parse_records(arcount, data, offset)

    return answers, authorities, additionals


def send_dns_query(domain_name, root_server_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

       # Use Part 2 (Builder)
    query, tx_id = build_dns_query(domain_name)

    # Below this is where the Query builder code should be (make sure to delete this once implemented)
    # Example:
    # dns_query = build_dns_query(domain_name)
    dns_query = b""  # TODO: replace with real DNS query

    server_address = (root_server_ip, 53)

    try:
        print(f"Sending DNS query to {root_server_ip} ...")
        sock.sendto(dns_query, server_address)

        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)

        # This is where the reply should be read from the Response Parser, delete once implemented

    # Use Part 3 (Parser)
        ans, auth, add = parse_response(data)
        return ans, auth, add

    except socket.timeout:
        print("DNS server did not respond (timeout).")
        return None, None, None

    finally:
        sock.close()


if __name__ == "__main__":
    # Main loop implementation to be done, remove this once finished.
    pass
