#!/usr/bin/env python3
# readv2.py - MitM: lee tráfico ICMP de un .pcapng y descifra el mensaje César
# Uso: sudo python3 readv2.py <archivo.pcapng>
# Ejemplo: sudo python3 readv2.py cesar.pcapng
#
# Lee los paquetes ICMP Echo Request del archivo, extrae el carácter inyectado
# en cada uno, reconstruye el mensaje cifrado, aplica fuerza bruta sobre todos
# los desplazamientos posibles (0-25) e imprime en VERDE la opción más probable.

import sys
import struct
import os

# ──────────────────────────────────────────────
# Colores ANSI
GREEN  = "\033[92m"
RESET  = "\033[0m"
# ──────────────────────────────────────────────

# ──────────────────────────────────────────────
# Palabras comunes en español/inglés para scoring
COMMON_WORDS = {
    "de","en","la","el","los","las","un","una","y","a","que","es","se",
    "no","te","lo","le","da","su","por","con","una","para","al","del",
    "the","and","for","are","you","this","that","with","have","from",
    "criptografia","seguridad","redes","hola","mundo",
}
# ──────────────────────────────────────────────

def descifrar_cesar(texto, desplazamiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            resultado += chr((ord(char) - base - desplazamiento) % 26 + base)
        else:
            resultado += char
    return resultado

def score_texto(texto):
    """Puntaje basado en cuántas palabras comunes aparecen."""
    palabras = texto.lower().split()
    return sum(1 for p in palabras if p in COMMON_WORDS)

# ──────────────────────────────────────────────
# Parser PCAPNG mínimo
# ──────────────────────────────────────────────

def read_u32_le(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def parse_pcapng(filepath):
    """
    Extrae los bytes crudos de cada paquete capturado en el archivo pcapng.
    Soporta los bloques principales: SHB (0x0A0D0D0A), IDB (1), EPB (6), SPB (3).
    Devuelve lista de bytes (payload de cada frame).
    """
    with open(filepath, "rb") as f:
        data = f.read()

    packets = []
    offset = 0
    length = len(data)

    while offset + 8 <= length:
        block_type   = read_u32_le(data, offset)
        block_length = read_u32_le(data, offset + 4)

        if block_length < 12 or offset + block_length > length:
            break

        block_data = data[offset : offset + block_length]

        # Enhanced Packet Block (EPB) = tipo 6
        if block_type == 6:
            # interface_id(4) + timestamp_high(4) + timestamp_low(4) + cap_len(4) + orig_len(4) = 20 bytes cabecera interna
            cap_len = read_u32_le(block_data, 20)
            pkt_start = 28  # 8 (bloque) + 20 (cabecera EPB)
            if pkt_start + cap_len <= len(block_data):
                packets.append(block_data[pkt_start : pkt_start + cap_len])

        # Simple Packet Block (SPB) = tipo 3
        elif block_type == 3:
            cap_len = read_u32_le(block_data, 12)
            pkt_start = 16
            if pkt_start + cap_len <= len(block_data):
                packets.append(block_data[pkt_start : pkt_start + cap_len])

        offset += block_length

    return packets

def extract_icmp_data_byte(raw_packet):
    """
    Dado un frame Ethernet/IP/ICMP crudo, extrae el byte inyectado.
    
    Estructura esperada:
      Ethernet: 14 bytes
      IPv4 header: IHL * 4 bytes (mínimo 20)
      ICMP header: 8 bytes (type, code, checksum, id, seq)
      ICMP data: 48 bytes
        [0:8]   timestamp (tv_sec 4B + tv_usec 4B)
        [8:48]  patrón con carácter inyectado en posición (seq % 40)
    
    Devuelve (seq, char) o None si no es ICMP Echo Request.
    """
    if len(raw_packet) < 34:
        return None

    # Ethernet (14 bytes) → IP
    eth_type = struct.unpack_from(">H", raw_packet, 12)[0]
    if eth_type != 0x0800:   # Solo IPv4
        return None

    ip_start = 14
    ihl = (raw_packet[ip_start] & 0x0F) * 4
    protocol = raw_packet[ip_start + 9]
    if protocol != 1:        # Solo ICMP
        return None

    icmp_start = ip_start + ihl
    if len(raw_packet) < icmp_start + 8 + 48:
        return None

    icmp_type = raw_packet[icmp_start]
    if icmp_type != 8:       # Solo Echo Request
        return None

    seq = struct.unpack_from(">H", raw_packet, icmp_start + 6)[0]

    data_start = icmp_start + 8
    # Los primeros 8 bytes del data son el timestamp
    # El carácter inyectado está en posición (seq % 40) dentro del patrón (bytes 8-47)
    inject_pos = (seq % 40)
    char_byte = raw_packet[data_start + 8 + inject_pos]

    # Filtrar solo caracteres válidos: letras, espacio, o 'b' (último carácter)
    char = chr(char_byte)
    if not (char.isalpha() or char == ' '):
        return None

    return (seq, char)

def main():
    if len(sys.argv) < 2:
        print(f"Uso: sudo python3 {sys.argv[0]} <archivo.pcapng>")
        print(f"Ejemplo: sudo python3 {sys.argv[0]} cesar.pcapng")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: no se encontró el archivo '{filepath}'")
        sys.exit(1)

    # Parsear pcapng
    packets = parse_pcapng(filepath)
    if not packets:
        print("No se encontraron paquetes en el archivo.")
        sys.exit(1)

    # Extraer caracteres ICMP
    extraidos = {}
    for pkt in packets:
        result = extract_icmp_data_byte(pkt)
        if result:
            seq, char = result
            extraidos[seq] = char

    if not extraidos:
        print("No se encontraron paquetes ICMP Echo Request con datos inyectados.")
        sys.exit(1)

    # Reconstruir mensaje cifrado en orden de secuencia
    seq_ordenados = sorted(extraidos.keys())
    mensaje_cifrado = "".join(extraidos[s] for s in seq_ordenados)
    print(f"Mensaje cifrado interceptado: {mensaje_cifrado}\n")

    # Fuerza bruta: todos los desplazamientos 0-25
    scores = []
    for desp in range(26):
        texto = descifrar_cesar(mensaje_cifrado, desp)
        s = score_texto(texto)
        scores.append((desp, texto, s))

    mejor_score = max(s for _, _, s in scores)

    print(f"{'Desp':<6} {'Texto descifrado'}")
    print("-" * 70)
    for desp, texto, s in scores:
        if s == mejor_score and s > 0:
            linea = f"{desp:<6} {texto}"; print(f"{GREEN}{linea}{RESET}")
        else:
            print(f"{desp:<6} {texto}")

    print()
    mejor = max(scores, key=lambda x: x[2])
    print(f"Llave más probable: {mejor[0]}")
    print(f"Mensaje en claro : {mejor[1]}")

if __name__ == "__main__":
    main()