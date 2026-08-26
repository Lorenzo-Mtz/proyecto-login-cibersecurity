#convertir texto a bits
"""
def text_to_bits(a):
    text_bytes = a.encode('utf-8')  # Convierte el string a bytes usando UTF-8

    bits = ''.join(f'{b:08b}' for b in text_bytes)
    return bits




prueba = input("Ingrese un string para convertir a bits: ")
string_en_bits = text_to_bits(prueba)
len_string = len(string_en_bits)
print(f"El string '{prueba}' convertido a bits es: {string_en_bits}")
print(f"La longitud del string en bits es: {len_string} bits")

length = len_string.to_bytes(8, byteorder='little') # Representa la longitud en bits como un entero de 64 bits
bits_length = ''.join(f'{b:08b}' for b in length)

final =  string_en_bits + '1' + '0'*((448-(len_string+1))%512) + '' + bits_length
print(f"El string final con padding es: {final}")
print("Funciona:" + str(len(final)%512))  # Muestra la longitud final en bits



#convertir texto a bytes

def padding(text):
    text_bytes = text.encode('utf-8')
    len_text = len(text_bytes)
    bit_length = len_text*8
    len_bytes = bit_length.to_bytes(8, byteorder ='little')
    final = text_bytes + b'\x80' + b'\x00'*((56-len_text-1)%64)+len_bytes
    return final


prueba = "password"
print(padding(prueba))
"""


def g_formula(i):
    round = i//16
    if round == 0:
        return i
    elif round == 1:
        return (5*i + 1)%16
    elif round == 2:
        return (3*i + 5)%16
    else:
        return (7*i)%16


print(g_formula(31))
