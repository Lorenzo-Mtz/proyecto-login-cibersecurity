"""
Lab de Fase 0 — Implementacion de MD5 desde cero.

Objetivo: entender el algoritmo implementandolo, NO usarlo en produccion.
MD5 esta roto criptograficamente (colisiones conocidas) — nunca usar para
hashear contrasenas ni para nada que dependa de integridad/seguridad real.

Referencia para verificar tu resultado: compara contra hashlib.md5 al final.
"""

import hashlib
import math

#Constantes iniciales
A0 = 0x67452301
B0 = 0xefcdab89
C0 = 0x98badcfe
D0 = 0x10325476

def padding(text: bytes) -> bytes:
    len_text = len(text)
    bit_length = len_text*8
    len_bytes = bit_length.to_bytes(8, byteorder ='little')
    final = text + b'\x80' + b'\x00'*((56-len_text-1)%64)+len_bytes
    return final

def mask32(x):
    return x & 0xFFFFFFFF


def F(x,y,z):
    return (x & y) | (mask32(~x) & z)

def G(x,y,z):
    return (x & z) | (y & mask32(~z))

def H(x,y,z):
    return x ^ y ^ z

def I(x,y,z):
    return y ^ (x | mask32(~z))

def left_rotate(x, amount):
    r_side = x >> 32-amount
    l_side = x << amount
    return mask32(l_side | r_side)

def k_table(x):
    return math.floor(2**32 * abs(math.sin(x+1)))

k_list = [k_table(i) for i in range(64)]

s_list = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21]
funcs = [F,G,H,I]

def g_formula(i):
    rd = i//16
    if rd == 0:
        return i 
    elif rd == 1:
        return (5*i + 1)%16
    elif rd == 2:
        return (3*i + 5)%16
    else:
        return (7*i)%16

def partir(b):
    M=[]
    for i in range(16):
        chunk = b[i*4:4*i+4]
        M.append(int.from_bytes(chunk, byteorder ='little'))
    return M


def md5(msg: bytes) -> bytes:
    padded = padding(msg)
    A,B,C,D = A0, B0, C0, D0
    for i in range(0,len(padded),64):
        bloque = padded[i:i+64]
        M =partir(bloque)
        a,b,c,d = A,B,C,D

        for j in range(64):
            func = funcs[j // 16]
            f_val = func(b,c,d)
            g = g_formula(j)

            suma = mask32(a + f_val + k_list[j]+M[g])
            nuevo_b = mask32(b+left_rotate(suma,s_list[j]))

            #rotación de variables
            a = d
            d = c
            c = b
            b = nuevo_b

        A = mask32(A+a)
        B = mask32(B+b)
        C = mask32(C+c)
        D = mask32(D+d)

    digest = A.to_bytes(4, byteorder='little') + B.to_bytes(4, byteorder='little') + C.to_bytes(4, byteorder='little') + D.to_bytes(4, byteorder='little')
    return digest




if __name__ == "__main__":
    test_cases = [b"", b"abc", b"oablfdjsgdaldbqlwudbqd%$#_?**"]
    for case in test_cases:
        try:
            mine = md5(case).hex()
        except NotImplementedError:
            mine = "(sin implementar)"
        reference = hashlib.md5(case).hexdigest()
        print(f"input={case!r}")
        print(f"  tuyo:      {mine}")
        print(f"  hashlib:   {reference}")
        print(f"  coincide:  {mine == reference}")

