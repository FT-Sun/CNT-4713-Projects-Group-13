import random
import socket
import sys
import struct


# ================================
# PART 1 - BUILD DNS QUERY
# ================================
def build_dns_query(domain_name):
    query = bytearray()

    transaction_id = random.randint(0, 0xFFFF)
    query += transaction_id.to_bytes(2, "big")
    query += (0).to_bytes(2, "big")   # flags
    query += (1).to_bytes(2, "big")   # QDCOUNT
    query += (0).to_bytes(2, "big")   # ANCOUNT
    query += (0).to_bytes(2, "big")   # NSCOUNT
    query += (0).to_bytes(2, "big")   # ARCOUNT

    for part in domain_name.split("."):
        query += bytes([len(part)])
        query += part.encode("ascii")
    query += b"\x00"

    query += (1).to_bytes(2, "big")   # QTYPE = A
    query += (1).to_bytes(2, "big")   # QCLASS = IN

    return query, transaction_id


# ================================
# PART 2 - PARSE DNS RESPONSE
# ================================

def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True

        elif length == 0:
            offset += 1
            break

        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii"))
            offset += length

    if jumped:
        return ".".join(labels), original_offset
    return ".".join(labels), offset


def parse_records(count, data, offset):
    records = []

    for _ in range(count):
        name, offset = parse_name(data, offset)

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10

        rdata_offset = offset
        rdata = data[offset:offset + rdlength]

        if rtype == 1:
            ip = ".".join(str(b) for b in rdata)
            records.append({"name": name, "type": "A", "value": ip})

        elif rtype == 2:
            ns_name, _ = parse_name(data, rdata_offset)
            records.append({"name": name, "type": "NS", "value": ns_name})

        else:
            records.append({"name": name, "type": rtype, "value": "other"})

        offset += rdlength

    return records, offset


def parse_response(data):
    header = struct.unpack("!HHHHHH", data[:12])
    qdcount = header[2]
    ancount = header[3]
    nscount = header[4]
    arcount = header[5]

    offset = 12

    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4

    answers, offset = parse_records(ancount, data, offset)
    authorities, offset = parse_records(nscount, data, offset)
    additionals, offset = parse_records(arcount, data, offset)

    return answers, authorities, additionals


# ================================
# PART 3 - SEND DNS QUERY (SOCKET)
# ================================
def send_dns_query(domain_name, server_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    query, tx_id = build_dns_query(domain_name)

    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
        return parse_response(data)

    except socket.timeout:
        print("Timeout while waiting for reply from", server_ip)
        return None, None, None

    finally:
        sock.close()


# ================================
# PART 4 - MAIN LOGIC 
# ================================

def print_reply(server_ip, answers, authorities, additionals):
    print("----------------------------------------------------------------")
    print("DNS server to query:", server_ip)
    print("Reply received. Content overview:")
    print(str(len(answers)) + " Answers.")
    print(str(len(authorities)) + " Intermediate Name Servers.")
    print(str(len(additionals)) + " Additional Information Records.")

    print("Answers section:")
    for record in answers:
        if record["type"] == "A":
            print("Name :", record["name"], "IP :", record["value"])

    print("Authority Section:")
    for record in authorities:
        if record["type"] == "NS":
            print("Name :", record["name"], "Name Server :", record["value"])

    print("Additional Information Section:")
    for record in additionals:
        if record["type"] == "A":
            print("Name :", record["name"], "IP :", record["value"])

def choose_next_server(additionals):
    for record in additionals:
        if record["type"] == "A":
            return record["value"]
    return None

def main():
    if len(sys.argv) != 3:
        print("Usage: python mydns.py domain-name root-dns-ip")
        return

    domain_name = sys.argv[1]
    current_server = sys.argv[2]

    while True:
        answers, authorities, additionals = send_dns_query(domain_name, current_server)

        if answers is None:
            print("Failed to get DNS response.")
            return

        print_reply(current_server, answers, authorities, additionals)

        if len(answers) > 0:
            break

        next_server = choose_next_server(additionals)

        if next_server is None:
            print("No next DNS server found.")
            return

        current_server = next_server


# ================================
# RUN PROGRAM
# ================================
if __name__ == "__main__":
    main()