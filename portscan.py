#!/usr/bin/env python3

import os
import sys
import socket
import re
import ipaddress
from scapy.all import (
    IP, TCP, UDP, ICMP,
    Ether, ARP,
    sr1, srp,
    RandIP, conf,
    Scapy_Exception
)

conf.verb = 0
MAX_PORT = 65535

TOP_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 139, 143,
    443, 445, 3306, 3389
]

# =====================================================
# VALIDACAO DE ALVO (IP / DOMINIO)
# =====================================================

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

ONLY_IP_CHARS = re.compile(r"^[0-9.]+$")

def validate_target(target: str) -> str:
    target = target.strip()

    # URL ou caminho
    if "://" in target or "/" in target:
        print("[-] Entrada inválida: informe apenas IP ou hostname (sem http://, https:// ou barras).")
        sys.exit(1)

    # Apenas números (ex: 123456)
    if target.isdigit():
        print("[-] Entrada inválida: não é um IP nem um domínio válido.")
        sys.exit(1)

    # Tentativa clara de IP (números e pontos)
    if re.fullmatch(r"[0-9.]+", target):
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            print("[-] IP inválido: formato incorreto ou octetos fora do intervalo (0–255).")
            sys.exit(1)

    # Domínio com '..'
    if ".." in target:
        print("[-] Domínio inválido: contém rótulos vazios ('..').")
        sys.exit(1)

    # Regex de domínio
    if not DOMAIN_REGEX.fullmatch(target):
        print("[-] Domínio inválido: formato incorreto.")
        sys.exit(1)

    # DNS
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Domínio inexistente: falha na resolução DNS.")
        sys.exit(1)
    except UnicodeError:
        print("[-] Domínio inválido: erro de codificação.")
        sys.exit(1)


# =====================================================
# ARP
# =====================================================

def resolve_mac(ip: str) -> str | None:
    arp = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = broadcast / arp

    answered, _ = srp(pkt, timeout=2, verbose=False)

    if answered:
        return answered[0][1].hwsrc
    return None

# =====================================================
# MENUS
# =====================================================

def choose_scan() -> str:
    options = {
        "1": "syn",
        "2": "ack",
        "3": "udp",
        "4": "decoy"
    }

    print("""
Escolha o tipo de scan:
1 - TCP SYN Scan
2 - TCP ACK Scan
3 - UDP Scan
4 - Decoy Scan
""")

    choice = input("Opção: ").strip()

    if choice not in options:
        print("[-] Opção de scan inválida.")
        sys.exit(1)

    return options[choice]

def choose_ports():
    print("""
Escolha as portas:
1 - Portas padrão (22, 80, 443)
2 - Top portas (estilo Nmap)
3 - Porta específica
4 - Intervalo de portas
5 - Todas as portas (1-65535)
""")

    try:
        option = input("Opção: ").strip()

        if option == "1":
            return [22, 80, 443]

        if option == "2":
            return TOP_PORTS

        if option == "3":
            port = int(input("Digite a porta: "))
            if not 1 <= port <= MAX_PORT:
                raise ValueError("Porta fora do intervalo válido.")
            return [port]

        if option == "4":
            start = int(input("Porta inicial: "))
            end = int(input("Porta final: "))
            if not (1 <= start <= end <= MAX_PORT):
                raise ValueError("Intervalo de portas inválido.")
            return range(start, end + 1)

        if option == "5":
            print("[!] Scan completo pode ser demorado.")
            return range(1, MAX_PORT + 1)

        raise ValueError("Opção inválida.")

    except ValueError as e:
        print(f"[-] {e}")
        sys.exit(1)

# =====================================================
# FUNCOES DE SCAN
# =====================================================

def send_tcp(ip, port, flags, mac=None, src_ip=None):
    pkt = IP(dst=ip, src=src_ip)/TCP(dport=port, flags=flags)
    if mac:
        pkt = Ether(dst=mac)/pkt
    return sr1(pkt, timeout=1)

def syn_scan(ip, ports, mac):
    print("\n--- TCP SYN Scan ---")
    try:
        for port in ports:
            resp = send_tcp(ip, port, "S", mac)

            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:
                    print(f"Porta {port}: Open")
                elif resp[TCP].flags == 0x14:
                    print(f"Porta {port}: Closed")
            else:
                print(f"Porta {port}: Filtered")

    except KeyboardInterrupt:
        print("\n[!] Scan interrompido.")

def ack_scan(ip, ports, mac):
    print("\n--- TCP ACK Scan ---")
    try:
        for port in ports:
            resp = send_tcp(ip, port, "A", mac)
            print(f"Porta {port}: {'Unfiltered' if resp else 'Filtered'}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrompido.")

def udp_scan(ip, ports, mac):
    print("\n--- UDP Scan ---")
    try:
        for port in ports:
            pkt = IP(dst=ip)/UDP(dport=port)
            if mac:
                pkt = Ether(dst=mac)/pkt

            resp = sr1(pkt, timeout=2)

            if resp is None:
                print(f"Porta {port}: Open | Filtered")
            elif resp.haslayer(ICMP) and resp[ICMP].type == 3:
                print(f"Porta {port}: Closed")

    except KeyboardInterrupt:
        print("\n[!] Scan interrompido.")

def decoy_scan(ip, ports):
    print("\n--- Decoy Scan ---")
    try:
        for port in ports:
            resp = send_tcp(ip, port, "S", src_ip=RandIP())

            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:
                    print(f"Porta {port}: Open")
                elif resp[TCP].flags == 0x14:
                    print(f"Porta {port}: Closed")
            else:
                print(f"Porta {port}: Unknown")

    except KeyboardInterrupt:
        print("\n[!] Scan interrompido.")

# =====================================================
# MAIN
# =====================================================

def main():
    if os.geteuid() != 0:
        print("[-] Execute como root (sudo).")
        sys.exit(1)

    print("=== PortScanner Educacional (Scapy) ===")

    try:
        target = input("Digite o IP ou hostname do alvo: ").strip()
        ip = validate_target(target)

        mac = resolve_mac(ip)
        if mac:
            print(f"[+] MAC resolvido: {mac}")
        else:
            print("[*] Scan fora da LAN (ARP não aplicado).")

        scan_type = choose_scan()
        ports = choose_ports()

        if scan_type == "syn":
            syn_scan(ip, ports, mac)
        elif scan_type == "ack":
            ack_scan(ip, ports, mac)
        elif scan_type == "udp":
            udp_scan(ip, ports, mac)
        elif scan_type == "decoy":
            decoy_scan(ip, ports)

    except KeyboardInterrupt:
        print("\n[!] Execução cancelada pelo usuário.")
        sys.exit(0)

    except Scapy_Exception as e:
        print(f"[-] Erro Scapy: {e}")

if __name__ == "__main__":
    main()
