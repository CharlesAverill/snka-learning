#!/usr/bin/env python

import socket
import struct
import threading

HOST = "0.0.0.0"
PORT = 9000

# Struct format:
#   B  protocol      (uint8)
#   B  direction     (uint8)
#   H  src_port      (uint16)
#   H  dst_port      (uint16)
#   B  ttl           (uint8)
#   H  payload_len   (uint16)
#   4B src_ip octets (4 × uint8)
PACKET_STRUCT = struct.Struct("!BBHHBHBBBBx")
PACKET_FMT    = struct.Struct("!BBHHBHBBBB")
PACKET_SIZE   = PACKET_FMT.size


def parse_packet(data: bytes) -> dict:
    if len(data) != PACKET_SIZE:
        raise ValueError(f"expected {PACKET_SIZE} bytes, got {len(data)}")
    proto, direction, src_port, dst_port, ttl, length, ip0, ip1, ip2, ip3 = \
        PACKET_FMT.unpack(data)
    return {
        "proto":     proto,
        "dir":       direction,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "ttl":       ttl,
        "len":       length,
        "src_ip":    (ip0, ip1, ip2, ip3),
    }


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed before full packet received")
        buf.extend(chunk)
    return bytes(buf)


def is_rfc1918(ip):
    a, b, _, _ = ip
    return (
        a == 10
        or (a == 192 and b == 168)
        or (a == 172 and 16 <= b <= 31)
    )


def is_valid_proto(proto):
    return proto in (6, 17, 1)  # TCP, UDP, ICMP


def classify(pkt: dict) -> bool:
    proto     = pkt["proto"]
    direction = pkt["dir"]
    src_port  = pkt["src_port"]
    dst_port  = pkt["dst_port"]
    ttl       = pkt["ttl"]
    length    = pkt["len"]
    src_ip    = pkt["src_ip"]

    if not is_valid_proto(proto):
        return False
    if ttl <= 1:
        return False
    if length <= 0 or length > 9000:
        return False

    if direction == 0:          # Inbound
        if is_rfc1918(src_ip):  # drop spoofed private sources
            return False
        if proto != 6:          # only TCP
            return False
        if dst_port not in (80, 443):
            return False
        return True
    else:                       # Outbound
        if src_port > 1023:     # ephemeral source → allow
            return True
        if proto == 17 and dst_port == 53:   # DNS
            return True
        return False


def handle_client(conn: socket.socket):
    with conn:
        while True:
            try:
                data = recv_exact(conn, PACKET_SIZE)
            except EOFError:
                break

            try:
                pkt      = parse_packet(data)
                decision = classify(pkt)
                response = b"FWD" if decision else b"DRP"
                print(f"[*] {pkt}  →  {'FWD' if decision else 'DRP'}")
            except Exception as exc:
                print(f"[!] parse error: {exc}")
                response = b"DRP"

            try:
                conn.sendall(response)
            except Exception:
                break


def serve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Firewall oracle listening on {HOST}:{PORT} (binary protocol)")
        while True:
            conn, addr = s.accept()
            print(f"[+] connection from {addr}")
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve()
