import sys
from scapy.all import IP, ICMP, send

def enviar_paquetes_icmp(mensaje):
    destino = "8.8.8.8"
    for char in mensaje:
        paquete = IP(dst=destino)/ICMP()/char
        send(paquete, verbose=False)

if __name__ == "__main__":
    destino = "8.8.8.8"
    if len(sys.argv) != 2:
        print("Uso: python paquete.py \"<mensaje>\"")
        sys.exit(1)
    
    mensaje = sys.argv[1]

    enviar_paquetes_icmp(mensaje)
    print(f"Mensaje enviado a {destino} en paquetes ICMP separados.")
