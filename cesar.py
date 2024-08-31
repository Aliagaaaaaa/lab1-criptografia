import sys

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

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python cesar.py <texto> <corrimiento>")
        sys.exit(1)

    texto_a_cifrar = sys.argv[1]
    try:
        corrimiento = int(sys.argv[2])
    except ValueError:
        print("El corrimiento debe ser un número entero.")
        sys.exit(1)

    texto_cifrado = cifrar_cesar(texto_a_cifrar, corrimiento)
    print(f"Texto cifrado: {texto_cifrado}")