import sys
import socket
import struct
import logging
import warnings
import ipaddress 

# --- BLOCO DE SUPRESSÃO DE AVISOS ---
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# ------------------------------------

from scapy.all import IP, TCP, UDP, ICMP, sr1, conf, ARP, Ether, srp, get_if_list

# Configurações globais do Scapy
conf.verb = 0


def resolve_target(target):
    """
    Resolve hostname para IP e retorna um objeto ipaddress.IPv4Address.
    """
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(target)
            return ipaddress.ip_address(resolved_ip)
        except socket.gaierror:
            print(f"[-] Erro: Não foi possível resolver o alvo '{target}'")
            sys.exit(1)


def is_host_up(target_obj):
    """
    Verifica se o host está ativo usando APENAS ARP e ICMP (Ping),
    mas iterando interfaces para evitar bloqueios do Kernel.
    """
    target_str = str(target_obj)
    print(f"[*] Verificando se {target_str} está ativo (ARP/ICMP)...")

    # 1. Verifica Loopback (Localhost)
    if target_obj.is_loopback:
        print("[+] Host é Loopback (Localhost).")
        return True, "lo"

    # 2. Itera sobre todas as interfaces de rede disponíveis
    interfaces = get_if_list()
    for iface in interfaces:
        if iface == 'lo': continue 
        
        try:
            # Obtém o IP configurado na interface atual (Correção do Bug de Roteamento)
            # Isso impede que o Scapy envie pacote com IP de Wi-Fi saindo pelo Cabo e vice-versa
            my_ip_list = [x[4] for x in conf.route.routes if x[3] == iface and x[4] != '0.0.0.0']
            if not my_ip_list: continue
            my_ip = my_ip_list[0]

            # --- TENTATIVA 1: ARP (Camada 2 - Rede Local) ---
            # Envia ARP Request forçando a origem (psrc) e a interface
            arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_str, psrc=my_ip)
            ans, _ = srp(arp_pkt, timeout=0.8, verbose=0, iface=iface)
            
            if ans:
                print(f"[+] Host ativo detectado via ARP na interface {iface}.")
                return True, iface

            # --- TENTATIVA 2: ICMP Echo Request (Ping - Camada 3) ---
            # Envia Ping forçando a origem (src) para passar pelo rp_filter do Kernel
            ping_pkt = IP(dst=target_str, src=my_ip)/ICMP()
            res = sr1(ping_pkt, timeout=1, verbose=0, iface=iface)
            
            if res:
                print(f"[+] Host ativo detectado via ICMP (Ping) na interface {iface}.")
                return True, iface

        except Exception:
            # Se der erro numa interface (ex: interface down), pula para a próxima
            continue

    return False, None


def syn_scan(target, port):
    """TCP SYN Scan"""
    try:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response is None:
            return "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: # SYN-ACK
                sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "Open"
            elif response.getlayer(TCP).flags == 0x14: # RST-ACK
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
            return "Open | Filtered"
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
            if response.getlayer(TCP).flags == 0x04: # RST
                return "Unfiltered"
        return "Filtered"
    except (struct.error, OverflowError):
        return "Invalid Port"


def parse_ports(ports_input):
    """Trata entradas de portas."""
    ports = []
    for part in ports_input.replace(',', ' ').split():
        try:
            if '-' in part:
                start, end = map(int, part.split('-'))
                for p in range(start, end + 1):
                    if 0 <= p <= 65535: ports.append(p)
            else:
                p = int(part)
                if 0 <= p <= 65535: ports.append(p)
        except ValueError:
            pass
    return sorted(list(set(ports)))


def main():
    print("\n" + "="*25)
    print("   SCAPY PORT SCANNER ")
    print("="*25 + "\n")
    
    try:
        target_input = input("Digite o Alvo (IP ou Hostname): ")
        target_obj = resolve_target(target_input)
        
        # Chama a função simplificada (Só ARP/Ping)
        is_up, found_iface = is_host_up(target_obj)

        if not is_up:
            confirm = input("[!] Host parece offline (Sem resposta ARP/Ping). Continuar? (s/n): ")
            if confirm.lower() != 's': return
        else:
            if found_iface and found_iface != 'lo':
                conf.iface = found_iface
                print(f"[*] Interface definida para o scan: {found_iface}")

        target_ip_str = str(target_obj)
        
        print(f"\n[*] Alvo definido: {target_ip_str}")
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
            if choice == '1': result = syn_scan(target_ip_str, port)
            elif choice == '2': result = udp_scan(target_ip_str, port)
            elif choice == '3': result = ack_scan(target_ip_str, port)
            else: break
            print(f"{port:<10} {result:<15}")

        print("\n[+] Scan finalizado com sucesso.")

    except KeyboardInterrupt:
        print("\n\n[!] Interrompido pelo usuário. Saindo...")
    except Exception as e:
        print(f"\n[!] Erro crítico no sistema: {e}")


if __name__ == "__main__":
    main()
