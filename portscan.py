import sys
import socket
import struct
from scapy.all import IP, TCP, UDP, ICMP, sr1, conf, ARP, Ether, srp

conf.verb = 0


def resolve_target(target):
    """Resolve hostname para IP ou valida o IP de entrada."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Erro: Não foi possível resolver o alvo '{target}'")
        sys.exit(1)


def is_host_up(target_ip):
    """Verifica se o host está ativo antes de iniciar o scan."""
    print(f"[*] Verificando se {target_ip} está ativo...")

    arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
    ans, _ = srp(arp_pkt, timeout=2, verbose=0)
    if ans:
        print("[+] Host ativo detectado via ARP (Rede Local).")
        return True

    ping_pkt = IP(dst=target_ip)/ICMP()
    res = sr1(ping_pkt, timeout=2, verbose=0)
    if res:
        print("[+] Host ativo detectado via ICMP.")
        return True

    return False


def syn_scan(target, port):
    """TCP SYN Scan"""
    try:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            return "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "Open"
            elif response.getlayer(TCP).flags == 0x14:
                return "Closed"
        return "Unknown"
    except (struct.error, OverflowError):
        return "Invalid Port"


def udp_scan(target, port):
    """UDP Scan"""
    try:
        packet = IP(dst=target)/UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            return "Filtered"
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3:
                if int(response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    return "Filtered"
                elif int(response.getlayer(ICMP).code) == 3:
                    return "Closed"
        return "Open"
    except (struct.error, OverflowError):
        return "Invalid Port"


def ack_scan(target, port):
    """TCP ACK Scan"""
    try:
        packet = IP(dst=target)/TCP(dport=port, flags="A")
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            return "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x04:  # RST
                return "Unfiltered"
        return "Filtered"
    except (struct.error, OverflowError):
        return "Invalid Port"


def parse_ports(ports_input):
    """Trata entradas como '22', '80-100', '443' e valida o range de 16 bits."""
    ports = []
    for part in ports_input.replace(',', ' ').split():
        try:
            if '-' in part:
                start, end = map(int, part.split('-'))
                for p in range(start, end + 1):
                    if 0 <= p <= 65535:
                        ports.append(p)
                    else:
                        print(
                            f"[!] Porta {p} ignorada (fora do intervalo 0-65535).")
            else:
                p = int(part)
                if 0 <= p <= 65535:
                    ports.append(p)
                else:
                    print(
                        f"[!] Porta {p} ignorada (fora do intervalo 0-65535).")
        except ValueError:
            print(f"[!] Entrada '{part}' inválida ignorada.")
    return sorted(list(set(ports)))


def main():
    print("\n" + "="*25)
    print("   SCAPY PORT SCANNER ")
    print("="*25 + "\n")

    try:
        target_input = input("Digite o Alvo (IP ou Hostname): ")
        target_ip = resolve_target(target_input)

        if not is_host_up(target_ip):
            confirm = input(
                "[!] Host parece offline. Continuar mesmo assim? (s/n): ")
            if confirm.lower() != 's':
                return

        print(f"\n[*] Alvo definido: {target_ip}")
        print("\nEscolha o tipo de Scan:")
        print("1. TCP SYN Scan")
        print("2. UDP Scan")
        print("3. TCP ACK Scan")

        choice = input("\nSelecione (1-3): ")
        ports_str = input("Digite as portas (ex: 22, 80-100, 443): ")
        ports = parse_ports(ports_str)

        if not ports:
            print("[-] Nenhuma porta válida para escanear.")
            return

        print(f"\n[!] Iniciando scan em {len(ports)} porta(s)...")
        print(f"\n{'PORTA':<10} {'ESTADO':<15}")
        print("-" * 30)

        for port in ports:
            if choice == '1':
                result = syn_scan(target_ip, port)
            elif choice == '2':
                result = udp_scan(target_ip, port)
            elif choice == '3':
                result = ack_scan(target_ip, port)
            else:
                print("Opção inválida.")
                break

            print(f"{port:<10} {result:<15}")

        print("\n[+] Scan finalizado com sucesso.")

    except KeyboardInterrupt:
        print("\n\n[!] Interrompido pelo usuário. Saindo...")
    except Exception as e:
        print(f"\n[!] Erro crítico no sistema: {e}")


if __name__ == "__main__":
    main()
