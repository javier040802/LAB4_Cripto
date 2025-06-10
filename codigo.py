#codigo.py *                                                                                                                                                                                                                                                                                                                # codigo.py
# -*- coding: utf-8 -*-

import sys
from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def ajustar_bytes(b: bytes, longitud_objetivo: int) -> bytes:
    longitud_original = len(b)
    if longitud_original < longitud_objetivo:
        faltantes = longitud_objetivo - longitud_original
        print(f"   La entrada tiene {longitud_original} bytes; "
              f"se completarán {faltantes} bytes aleatorios.")
        b += get_random_bytes(faltantes)
    elif longitud_original > longitud_objetivo:
        print(f"   La entrada tiene {longitud_original} bytes; "
              f"se truncarán {longitud_original - longitud_objetivo} bytes.")
        b = b[:longitud_objetivo]
    else:
        print(f"   La entrada tiene {longitud_original} bytes; no se ajusta.")
    return b


def procesar_algoritmo(
    nombre: str,
    modulo_cipher,
    tam_clave: int,
    tam_iv: int,
    texto_plano: str
):
    print("\n" + "-"*60)
    print(f" Procesando algoritmo: {nombre} ")
    print("-"*60 + "\n")

    clave_input = input(f"Ingrese la clave para {nombre} (texto plano): ")
    clave_bytes = clave_input.encode('utf-8')
    print(f"  Clave ingresada (en bytes): {len(clave_bytes)} bytes.")
    clave_final = ajustar_bytes(clave_bytes, tam_clave)
    print(f"  → Clave FINAL para {nombre} (hex): {clave_final.hex()}\n")

    iv_input = input(f"Ingrese el Vector de Inicialización (IV) para {nombre} (texto plano): ")
    iv_bytes = iv_input.encode('utf-8')
    print(f"  IV ingresado (en bytes): {len(iv_bytes)} bytes.")
    iv_final = ajustar_bytes(iv_bytes, tam_iv)
    print(f"  → IV FINAL para {nombre} (hex): {iv_final.hex()}\n")

    cipher_enc = modulo_cipher.new(clave_final, modulo_cipher.MODE_CBC, iv_final)
    texto_bytes = texto_plano.encode('utf-8')
    bloque_size = tam_iv
    texto_padded = pad(texto_bytes, bloque_size)
    print(f"  Texto plano antes de padding: {len(texto_bytes)} bytes.")
    print(f"  Texto plano con padding PKCS7: {len(texto_padded)} bytes.\n")

    ciphertext = cipher_enc.encrypt(texto_padded)
    ciphertext_hex = ciphertext.hex()
    print(f"  → Texto CIFRADO ({nombre}) (hex local):")
    print(f"     {ciphertext_hex}\n")

    cipher_dec = modulo_cipher.new(clave_final, modulo_cipher.MODE_CBC, iv_final)
    texto_descifrado_padded = cipher_dec.decrypt(ciphertext)
    try:
        texto_desc = unpad(texto_descifrado_padded, bloque_size).decode('utf-8')
        print(f"  → Texto DESCIFRADO ({nombre}): {texto_desc}")
    except ValueError:
        print("  El padding es inválido al descifrar. No se pudo obtener el texto plano.\n")
    print("\n" + "-"*60 + "\n")


def main():
    print("\n" + "="*70)
    print("   Programa de cifrado y descifrado con DES, AES-256 y 3DES (modo CBC)")
    print("="*70 + "\n")

    texto_plano = input("1) Ingrese el texto a cifrar (texto plano): ").strip()
    if texto_plano == "":
        print("  Debes ingresar un texto para cifrar. Saliendo...")
        sys.exit(1)

    procesar_algoritmo(
        nombre="DES",
        modulo_cipher=DES,
        tam_clave=8,
        tam_iv=8,
        texto_plano=texto_plano
    )

    procesar_algoritmo(
        nombre="AES-256",
        modulo_cipher=AES,
        tam_clave=32,
        tam_iv=16,
        texto_plano=texto_plano
    )

    procesar_algoritmo(
        nombre="3DES",
        modulo_cipher=DES3,
        tam_clave=24,
        tam_iv=8,
        texto_plano=texto_plano
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPrograma detenido por el usuario. Saliendo...")
        sys.exit(0)








