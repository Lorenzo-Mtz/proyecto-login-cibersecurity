"""
Lab de Fase 0 — Implementacion de SHA-256 desde cero.

Objetivo: entender el algoritmo implementandolo, NO usarlo en produccion.
SHA-256 no esta roto (a diferencia de MD5), pero sigue siendo un hash RAPIDO:
por eso tampoco se usa a secas para contrasenas. Para contrasenas se usan
funciones lentas y con salt (bcrypt, scrypt, Argon2). Ver notas 2.2.

Diferencias clave contra tu md5_lab.py (leelas antes de empezar):
  1. ENDIANNESS: MD5 es little-endian en todo (longitud, palabras, digest).
     SHA-256 es BIG-ENDIAN en todo. Es el error numero 1 al portar el codigo.
  2. ESTADO: MD5 usa 4 registros (A,B,C,D) -> 128 bits.
     SHA-256 usa 8 registros (a..h) -> 256 bits.
  3. RONDAS: MD5 hace 64 rondas con 4 funciones distintas (F,G,H,I) y accede a
     M[g] con una permutacion. SHA-256 hace 64 rondas con las MISMAS
     operaciones, pero antes expande los 16 words del bloque a 64
     (message schedule). Ya no hay g_formula.
  4. ROTACION: MD5 solo rota a la izquierda. SHA-256 usa rotacion a la derecha
     (rotr) y desplazamiento a la derecha (shr) — ojo, NO son lo mismo.

Referencia oficial: FIPS 180-4 (NIST).
Verificacion: compara contra hashlib.sha256 al final.
"""

import hashlib
import math

# ---------------------------------------------------------------------------
# 1. Constantes iniciales (H0..H7)
# ---------------------------------------------------------------------------
# Son los primeros 32 bits de la parte fraccionaria de la RAIZ CUADRADA de los
# primeros 8 numeros primos (2, 3, 5, 7, 11, 13, 17, 19).

H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def mask32(x):
    """Trunca a 32 bits. Igual que en md5_lab.py."""
    return x & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# 2. Tabla K (64 constantes de ronda)
# ---------------------------------------------------------------------------
# Primeros 32 bits de la parte fraccionaria de la RAIZ CUBICA de los primeros
# 64 primos. Es el analogo de tu k_table(i) = floor(2**32 * abs(sin(i+1))).
#
# Reto opcional (recomendado, es lo mismo que hiciste en MD5): generalas tu.
#   - Necesitas los primeros 64 primos.
#   - raiz cubica: p ** (1/3)
#   - parte fraccionaria: x - floor(x)
#   - primeros 32 bits: floor(frac * 2**32)
#   - CUIDADO: el float de Python (64 bits) tiene precision justa aqui; si algun
#     valor sale desviado por 1, rehazlo con el modulo `decimal` subiendo
#     getcontext().prec.

def es_primo(n: int) -> bool:
    """Devuelve True si n es primo (divide por tentativa hasta n//2)."""
    if n < 2:
        return False
    for i in range(2,n//2+1):
        if n % i == 0:
            return False
    return True
   



def primeros_primos(cantidad: int) -> list:
    """Devuelve los primeros `cantidad` numeros primos, empezando en 2."""
    primos = []
    i = 2
    while len(primos) < cantidad:
        if es_primo(i):
            primos.append(i)
        i +=1
    return primos    
    


def k_table(p: int) -> int:
    """Primeros 32 bits de la parte fraccionaria de la raiz cubica de p."""
    return math.floor((p**(1/3) % 1) * 2**32)
    
   


# Tabla oficial de FIPS 180-4, solo como referencia para verificar la tuya.
K_OFICIAL = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


# La tabla que usa el algoritmo es la que generas tu. Si no coincide con
# K_OFICIAL, el bloque __main__ te avisa.
k_list = [k_table(p) for p in primeros_primos(64)]

# ---------------------------------------------------------------------------
# 3. Padding
# ---------------------------------------------------------------------------

def padding(text: bytes) -> bytes:
    """Anade 0x80, ceros y la longitud en bits (8 bytes, big-endian).

    El resultado siempre es multiplo de 64 bytes (512 bits).
    """
    len_string = len(text)
    bit_length = len_string*8
    len_bytes = bit_length.to_bytes(8, byteorder ='big')
    final = text + b'\x80' + b'\x00'*((56-len_string-1)%64)+len_bytes
    return final
    


# ---------------------------------------------------------------------------
# 4. Operaciones de bits
# ---------------------------------------------------------------------------

def rotr(x: int, n: int) -> int:
    """Rotacion a la derecha de 32 bits: lo que sale por la derecha reentra
    por la izquierda. Espejo de left_rotate() de md5_lab.py."""
    r_side = x >> n
    l_side = x << 32-n
    return mask32(l_side | r_side)


def shr(x: int, n: int) -> int:
    """Desplazamiento a la derecha: los bits que salen se pierden."""
    return x >> n
    


# ---------------------------------------------------------------------------
# 5. Funciones logicas (FIPS 180-4, seccion 4.1.2)
# ---------------------------------------------------------------------------

def ch(x, y, z):
    """Choose: bit a bit, x decide si tomar el bit de y o el de z."""
    return (x & y) ^ (mask32(~x) & z)
    


def maj(x, y, z):
    """Majority: cada bit es el valor mayoritario entre x, y y z."""
    return (x & y) ^ (x & z) ^ (y & z)
    


def sigma_may_0(x):
    """Sigma mayuscula 0, usada en el bucle de compresion (solo rotaciones)."""
    return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)
    


def sigma_may_1(x):
    """Sigma mayuscula 1, usada en el bucle de compresion (solo rotaciones)."""
    return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25)
    


def sigma_min_0(x):
    """Sigma minuscula 0, usada en el message schedule. La ultima es SHIFT."""
    return rotr(x,7) ^ rotr(x,18) ^ shr(x,3)
    


def sigma_min_1(x):
    """Sigma minuscula 1, usada en el message schedule. La ultima es SHIFT."""
    return rotr(x,17) ^ rotr(x,19) ^ shr(x,10)
   


# ---------------------------------------------------------------------------
# 6. Message schedule
# ---------------------------------------------------------------------------

def partir(bloque: bytes) -> list:
    """Parte un bloque de 64 bytes en 16 words de 32 bits, big-endian."""
    M = []
    for i in range(16):
        chunk = bloque[i*4:i*4+4]
        M.append(int.from_bytes(chunk, byteorder='big'))
    return M
    


def expandir(w: list) -> list:
    """Expande los 16 words del bloque a los 64 del message schedule."""
    for i in range(16,64):
        w.append(mask32(w[i-16] + sigma_min_0(w[i-15]) + w[i-7] + sigma_min_1(w[i-2])))
    return w
    


# ---------------------------------------------------------------------------
# 7. Bucle principal
# ---------------------------------------------------------------------------

def sha256(msg: bytes) -> bytes:
    """Calcula el hash SHA-256 de `msg` y lo devuelve como 32 bytes.

    Procesa el mensaje en bloques de 64 bytes: expande cada bloque a 64 words,
    corre 64 rondas sobre 8 registros y suma el resultado al estado `h`.
    """
    padded = padding(msg)
    h = list(H_INIT)
    for i in range(0,len(padded),64):
        bloque = padded[i:i+64]
        w = expandir(partir(bloque))
        a,b,c,d,e,f,g,hh = h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]

        for j in range(64):
            t1 = hh + sigma_may_1(e) + ch(e,f,g) + k_list[j] + w[j]
            t2 = sigma_may_0(a) + maj(a,b,c)

            hh = g
            g = f
            f = e
            e = mask32(d + t1)
            d = c
            c = b
            b = a
            a = mask32(t1 + t2)

        for k, val in enumerate((a,b,c,d,e,f,g,hh)):
            h[k] = mask32(h[k]+val)

    digest = b''.join(x.to_bytes(4, byteorder='big') for x in h)
    return digest

    


if __name__ == "__main__":
    # Los dos primeros son los vectores oficiales de FIPS 180-4:
    #   b""    -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #   b"abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    # Los dos ultimos pasan de 55 bytes, asi que obligan a un segundo bloque:
    # son la prueba real de que tu padding esta bien.
    test_cases = [
        b"",
        b"abc",
        b"oablfdjsgdaldbqlwudbqd%$#_?**",
        b"a" * 64,
        b"El login seguro no depende de un solo hash, sino de todo el flujo.",
    ]

    if k_list != K_OFICIAL:
        print("[!] Tu k_list NO coincide con la tabla oficial. Revisa k_table().")

    for case in test_cases:
        try:
            mine = sha256(case).hex()
        except NotImplementedError:
            mine = "(sin implementar)"
        reference = hashlib.sha256(case).hexdigest()
        print(f"input={case!r}")
        print(f"  tuyo:      {mine}")
        print(f"  hashlib:   {reference}")
        print(f"  coincide:  {mine == reference}")
