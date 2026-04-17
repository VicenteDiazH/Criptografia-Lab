#!/usr/bin/env python3
# cesar.py - Cifrado César
# Uso: python3 cesar.py "<texto>" <desplazamiento>
# Ejemplo: python3 cesar.py "criptografia y seguridad en redes" 9

import sys

def cifrar_cesar(texto, desplazamiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            resultado += chr((ord(char) - base + desplazamiento) % 26 + base)
        else:
            resultado += char
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Uso: python3 {sys.argv[0]} \"<texto>\" <desplazamiento>")
        sys.exit(1)

    texto = sys.argv[1]
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("Error: El desplazamiento debe ser un número entero.")
        sys.exit(1)

    cifrado = cifrar_cesar(texto, desplazamiento)
    print(cifrado)