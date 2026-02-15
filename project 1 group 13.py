#!/usr/bin/env python3


import sys
import socket
import os
import getpass

# FTP commands must end with carriage return + line feed
CRLF = "\r\n"

# Buffer size when receiving data
BUF = 4096

# Global control socket (persistent connection to server)
ctrl_sock = None

# Buffer used when reading control replies
ctrl_buf = b""


# ------------------------------------------------------------
# CONTROL CONNECTION FUNCTIONS
# ------------------------------------------------------------

def read_line():
    """
    Reads one line (ending in CRLF) from the control connection.
    FTP replies are text-based.
    """
    global ctrl_buf

    # Keep reading until we see CRLF
    while b"\r\n" not in ctrl_buf:
        data = ctrl_sock.recv(BUF)
        if not data:
            break
        ctrl_buf += data

    # Split one line from buffer
    if b"\r\n" in ctrl_buf:
        line, ctrl_buf = ctrl_buf.split(b"\r\n", 1)
    else:
        line, ctrl_buf = ctrl_buf, b""

    return line.decode("utf-8", errors="replace")


def read_reply():
    """
    Reads full FTP reply.
    FTP replies start with a 3-digit code.
    Handles both single-line and multi-line replies.
    Returns (code, full_message).
    """
    first = read_line()
    if not first:
        return None, ""

    lines = [first]

    # If first 3 characters are digits → valid reply
    if len(first) >= 3 and first[:3].isdigit():
        code = int(first[:3])

        # Multi-line reply (format: 123-...)
        if len(first) >= 4 and first[3] == "-":
            while True:
                line = read_line()
                if not line:
                    break
                lines.append(line)

                # End when we see "123 " (code + space)
                if line.startswith(str(code) + " "):
                    break

        return code, "\n".join(lines)

    return None, "\n".join(lines)


def send_cmd(cmd):
    """
    Sends a command to the FTP server over the control connection.
    """
    if not cmd.endswith(CRLF):
        cmd += CRLF
    ctrl_sock.sendall(cmd.encode("ascii", errors="ignore"))


def cmd_and_reply(cmd):
    """
    Sends a command and immediately reads its reply.
    """
    send_cmd(cmd)
    return read_reply()


def connect_control(host):
    """
    Creates the main FTP control connection (port 21).
    """
    global ctrl_sock
    try:
        ctrl_sock = socket.create_connection((host, 21), timeout=10)
        ctrl_sock.settimeout(10)

        # Read server greeting (usually 220)
        code, _ = read_reply()
        return code is not None and 200 <= code < 400
    except:
        return False


# ------------------------------------------------------------
# PASSIVE MODE (DATA CONNECTION)
# ------------------------------------------------------------

def pasv():
    """
    Sends PASV command.
    Parses server reply:
    227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)

    Calculates real IP and port.
    """
    code, msg = cmd_and_reply("PASV")
    if code != 227:
        return None, None

    # Extract numbers inside parentheses
    left = msg.find("(")
    right = msg.find(")")
    if left == -1 or right == -1:
        return None, None

    parts = msg[left + 1:right].split(",")
    if len(parts) != 6:
        return None, None

    # Build IP and calculate port
    h1, h2, h3, h4, p1, p2 = parts
    ip = ".".join([h1, h2, h3, h4])
    port = int(p1) * 256 + int(p2)

    return ip, port


def open_data_socket():
    """
    Opens the data connection after PASV.
    Used for ls, get, put.
    """
    ip, port = pasv()
    if ip is None:
        return None

    try:
        ds = socket.create_connection((ip, port), timeout=10)
        ds.settimeout(10)
        return ds
    except:
        return None


def recv_all(sock):
    """
    Receives all data from a data socket until closed.
    """
    data = b""
    while True:
        chunk = sock.recv(BUF)
        if not chunk:
            break
        data += chunk
    return data


# ------------------------------------------------------------
# FTP COMMANDS
# ------------------------------------------------------------

def do_login():
    """
    Handles USER and PASS login.
    """
    user = input("Username: ").strip()
    pw = getpass.getpass("Password: ")

    # Send USER command
    code, _ = cmd_and_reply("USER " + user)

    if code == 230:
        print("Success")
        return True

    if code != 331:
        print("Failure")
        return False

    # Send PASS command
    code, _ = cmd_and_reply("PASS " + pw)

    if code == 230:
        print("Success")
        return True

    print("Failure")
    return False


def do_ls():
    """
    Lists remote directory using LIST.
    """
    ds = open_data_socket()
    if ds is None:
        print("Failure")
        return

    send_cmd("LIST")
    code, _ = read_reply()

    if code not in (125, 150):
        ds.close()
        print("Failure")
        return

    listing = recv_all(ds)
    ds.close()

    code, _ = read_reply()

    if code is not None and 200 <= code < 300:
        print(listing.decode("utf-8", errors="replace"))
        print("Success")
    else:
        print("Failure")


def do_cd(remote_dir):
    """
    Changes remote directory.
    """
    code, _ = cmd_and_reply("CWD " + remote_dir)

    if code is not None and 200 <= code < 300:
        print("Success")
    else:
        print("Failure")


def do_get(remote_file):
    """
    Downloads file from server.
    """
    ds = open_data_socket()
    if ds is None:
        print("Failure")
        return

    send_cmd("RETR " + remote_file)
    code, _ = read_reply()

    if code not in (125, 150):
        ds.close()
        print("Failure")
        return

    data = recv_all(ds)
    ds.close()

    code, _ = read_reply()

    if code is None or not (200 <= code < 300):
        print("Failure")
        return

    # Save locally
    local_name = os.path.basename(remote_file)
    with open(local_name, "wb") as f:
        f.write(data)

    print("Success. Transferred {} bytes.".format(len(data)))


def do_put(local_file):
    """
    Uploads file to server.
    """
    try:
        with open(local_file, "rb") as f:
            data = f.read()
    except:
        print("Failure")
        return

    ds = open_data_socket()
    if ds is None:
        print("Failure")
        return

    remote_name = os.path.basename(local_file)

    send_cmd("STOR " + remote_name)
    code, _ = read_reply()

    if code not in (125, 150):
        ds.close()
        print("Failure")
        return

    ds.sendall(data)
    ds.close()

    code, _ = read_reply()

    if code is not None and 200 <= code < 300:
        print("Success. Transferred {} bytes.".format(len(data)))
    else:
        print("Failure")


def do_delete(remote_file):
    """
    Deletes remote file.
    """
    code, _ = cmd_and_reply("DELE " + remote_file)

    if code is not None and 200 <= code < 300:
        print("Success")
    else:
        print("Failure")


def do_quit():
    """
    Closes FTP session.
    """
    cmd_and_reply("QUIT")
    print("Success")


# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print("Usage: python myftp.py server-name")
        return

    host = sys.argv[1]

    # Connect to FTP server
    if not connect_control(host):
        print("Failure")
        return

    # Login first
    if not do_login():
        ctrl_sock.close()
        return

    # Command loop
    while True:
        line = input("myftp> ").strip()
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd == "ls":
            do_ls()
        elif cmd == "cd" and len(parts) > 1:
            do_cd(" ".join(parts[1:]))
        elif cmd == "get" and len(parts) > 1:
            do_get(" ".join(parts[1:]))
        elif cmd == "put" and len(parts) > 1:
            do_put(" ".join(parts[1:]))
        elif cmd == "delete" and len(parts) > 1:
            do_delete(" ".join(parts[1:]))
        elif cmd == "quit":
            do_quit()
            break
        else:
            print("Failure")

    ctrl_sock.close()


if __name__ == "__main__":
    main()
