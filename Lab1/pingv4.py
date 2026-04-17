#!/usr/bin/env python3
# pingv4.py - Modo Stealth: envía mensaje cifrado carácter a carácter en paquetes ICMP
# Uso: sudo python3 pingv4.py "<mensaje_cifrado>"
# Ejemplo: sudo python3 pingv4.py "larycxpajorj h bnpdarmjm nw anmnb"
#
# El último carácter del mensaje se transmite como una 'b'.
# El tráfico replica fielmente los campos de un ping real:
#   - Timestamp incremental coherente
#   - ICMP identification coherente
#   - Sequence number incremental
#   - Payload estándar de ping Linux (0x08 primeros bytes + 0x10-0x37 patrón estándar)

import sys
import time
import struct
import socket
import os
import random

def checksum(data):
    """Calcula checksum de Internet (RFC 1071)."""
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def build_icmp_packet(icmp_id, seq, data_byte, timestamp):
    """
    Construye un paquete ICMP Echo Request que replica fielmente un ping real de Linux.
    
    Estructura del payload de ping Linux (48 bytes total en data):
      - Bytes 0-7  : timestamp de 8 bytes (struct timeval: tv_sec 4B + tv_usec 4B)
      - Bytes 8-47 : patrón fijo 0x10, 0x11, ..., 0x37
                     EXCEPTO: el byte en posición (seq % 40 + 8) lleva el carácter del mensaje
    
    Nota: El último carácter del mensaje se transmite como ord('b').
    """
    icmp_type = 8   # Echo Request
    icmp_code = 0

    # Timestamp (primeros 8 bytes del data): tv_sec (4B) + tv_usec (4B)
    tv_sec  = int(timestamp)
    tv_usec = int((timestamp - tv_sec) * 1_000_000)
    ts_bytes = struct.pack(">II", tv_sec, tv_usec)

    # Patrón estándar de ping Linux: 0x10 a 0x37 (40 bytes)
    pattern = bytes(range(0x10, 0x38))  # 40 bytes

    # Inyectar el carácter del mensaje en la posición (seq % 40) del patrón
    pattern_list = list(pattern)
    inject_pos = seq % 40
    pattern_list[inject_pos] = data_byte
    payload = ts_bytes + bytes(pattern_list)  # 8 + 40 = 48 bytes

    # Cabecera ICMP sin checksum
    header = struct.pack(">BBHH", icmp_type, icmp_code, 0, icmp_id) + struct.pack(">H", seq)
    raw = header + payload
    csum = checksum(raw)
    header = struct.pack(">BBHH", icmp_type, icmp_code, csum, icmp_id) + struct.pack(">H", seq)

    return header + payload

def send_stealth_ping(message, target="127.0.0.1", interval=1.0):
    """
    Envía cada carácter del mensaje en un paquete ICMP separado.
    El último carácter se reemplaza por 'b' según el enunciado.
    """
    if not message:
        print("Error: el mensaje está vacío.")
        return

    chars = list(message)
    # El último carácter se transmite como 'b'
    chars[-1] = 'b'

    # ICMP identification: un valor fijo por sesión (como hace ping real)
    icmp_id = os.getpid() & 0xFFFF

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error: se necesitan privilegios de root (sudo).")
        sys.exit(1)

    base_time = time.time()

    for seq, char in enumerate(chars, start=1):
        data_byte = ord(char)
        ts = base_time + (seq - 1) * interval
        packet = build_icmp_packet(icmp_id, seq, data_byte, ts)

        try:
            sock.sendto(packet, (target, 0))
            print(f".")
            print(f"Sent 1 packets.")
        except Exception as e:
            print(f"Error enviando paquete {seq}: {e}")

        time.sleep(interval)

    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: sudo python3 {sys.argv[0]} \"<mensaje_cifrado>\"")
        print(f"Ejemplo: sudo python3 {sys.argv[0]} \"larycxpajorj h bnpdarmjm nw anmnb\"")
        sys.exit(1)

    message = sys.argv[1]
    target  = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

    send_stealth_ping(message, target)