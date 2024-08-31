import sys
from scapy.all import rdpcap, ICMP
from termcolor import colored

def cifrar_cesar(texto, corrimiento):
    corrimiento = corrimiento % 26
    texto_cifrado = ""

    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            nueva_pos = (ord(char) - base + corrimiento) % 26 + base
            texto_cifrado += chr(nueva_pos)
        else:
            texto_cifrado += char

    return texto_cifrado

def descifrar_todos(texto):
    posibles_descifrados = []
    for i in range(26):
        descifrado = cifrar_cesar(texto, -i)
        posibles_descifrados.append((i, descifrado))
    return posibles_descifrados

def es_mensaje_probable(mensaje):
    palabras_comunes = [
        'el', 'la', 'de', 'que', 'en', 'un', 'ser', 'se', 'no', 'haber', 
        'por', 'con', 'para', 'como', 'estar', 'tener', 'le', 'lo', 'todo', 'pero', 
        'más', 'hacer', 'poder', 'decir', 'este', 'otro', 'ese', 'ver', 'porque', 'dar', 'cuando', 'muy', 'sin', 'vez', 
        'mucho', 'saber', 'qué', 'sobre', 'seguridad', 'mi'
    ]
    
    palabras = mensaje.split()
    
    contador = 0
    for palabra in palabras:
        if palabra.lower() in palabras_comunes:
            contador += 1
    
    umbral = 1

    return contador >= umbral

def analizar_pcapng(archivo_pcapng):
    paquetes = rdpcap(archivo_pcapng)
    mensaje_completo = ""

    for paquete in paquetes:
        if ICMP in paquete and paquete[ICMP].type == 8:
            data = bytes(paquete[ICMP].payload).decode('utf-8', errors='ignore')
            mensaje_completo += data

    descifrados = descifrar_todos(mensaje_completo)
    
    for i, (corrimiento, descifrado) in enumerate(descifrados):
        if es_mensaje_probable(descifrado):
            print(colored(f"Posible descifrado con corrimiento {corrimiento}: {descifrado}", "green"))
        else:
            print(f"Posible descifrado con corrimiento {corrimiento}: {descifrado}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python analizar_pcapng.py <archivo.pcapng>")
        sys.exit(1)
    
    archivo_pcapng = sys.argv[1]
    analizar_pcapng(archivo_pcapng)
