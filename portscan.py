from scapy.all import IP, TCP, UDP, ICMP, sr1, conf, ARP, Ether, srp, get_if_list
import sys
import socket
import struct
import logging
import warnings

# --- BLOCO DE SUPRESSÃO DE AVISOS ---
# Silencia warnings chatos do Scapy
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# ------------------------------------


# Configurações globais do Scapy
conf.verb = 0


def resolve_target(target):
    """Resolve hostname para IP ou valida o IP de entrada."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Erro: Não foi possível resolver o alvo '{target}'")
        sys.exit(1)


def is_host_up(target_ip):
    """
    Verifica se o host está ativo usando múltiplas técnicas para contornar
    problemas de roteamento e isolamento de interface.
    Retorna: (True, nome_da_interface) ou (False, None)
    """
    print(f"[*] Verificando se {target_ip} está ativo...")

    # 1. TENTATIVA VIA SOCKET DO SISTEMA (Bypass do Scapy)
    # Deixa o Kernel do Linux decidir a rota. É o método mais robusto para cross-subnet.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        # Tenta conectar na porta 80 (HTTP) ou 443 (HTTPS) ou 445 (SMB)
        # Se der erro 111 (Connection Refused), o host ESTÁ VIVO, só a porta está fechada.
        res = s.connect_ex((target_ip, 80))
        s.close()

        # 0 = Aberta, 111 = Recusada (Linux), 10061 = Recusada (Windows)
        if res == 0 or res == 111 or res == 10061:
            print("[+] Host detectado via Tabela de Roteamento do SO (TCP).")
            return True, None  # None = deixa o SO decidir a interface
    except:
        pass

    # 2. TENTATIVA VIA SCAPY (Iteração de Interfaces)
    interfaces = get_if_list()
    for iface in interfaces:
        if iface == 'lo':
            continue  # Pula localhost

        try:
            # Obtém o IP da interface atual para evitar IP Spoofing
            my_ip_list = [x[4] for x in conf.route.routes if x[3]
                          == iface and x[4] != '0.0.0.0']
            if not my_ip_list:
                continue
            my_ip = my_ip_list[0]

            # A. Tentativa ARP (Camada 2 - Mesma Sub-rede)
            arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                ARP(pdst=target_ip, psrc=my_ip)
            ans, _ = srp(arp_pkt, timeout=0.8, verbose=0, iface=iface)
            if ans:
                print(
                    f"[+] Host ativo detectado via ARP na interface {iface}.")
                return True, iface

            # B. Tentativa ICMP (Camada 3 - Ping)
            ping_pkt = IP(dst=target_ip, src=my_ip)/ICMP()
            res = sr1(ping_pkt, timeout=0.8, verbose=0, iface=iface)
            if res:
                print(
                    f"[+] Host ativo detectado via ICMP na interface {iface}.")
                return True, iface
        except:
            continue

    # 3. TENTATIVA FINAL: TCP SYN PING (Força Bruta)
    print("[-] ARP e ICMP falharam. Tentando TCP SYN Discovery...")
    for dport in [80, 443, 22]:
        try:
            # Envia pacote SYN sem forçar interface, deixa o scapy resolver
            pkt = IP(dst=target_ip)/TCP(dport=dport, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp:
                print(f"[+] Host respondeu ao TCP SYN na porta {dport}.")
                return True, conf.iface
        except:
            pass

    return False, None


def syn_scan(target, port):
    """TCP SYN Scan"""
    try:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            return "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                # Envia RST para não deixar a conexão pendurada
                sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "Open"
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
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
            # Tipos e códigos ICMP que indicam filtragem ou porta fechada
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
    # Remove vírgulas e separa por espaços
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
    return sorted(list(set(ports)))  # Remove duplicatas e ordena


def main():
    print("\n" + "="*25)
    print("   SCAPY PORT SCANNER ")
    print("="*25 + "\n")

    try:
        target_input = input("Digite o Alvo (IP ou Hostname): ")
        target_ip = resolve_target(target_input)

        # Chama a nova função de discovery
        is_up, found_iface = is_host_up(target_ip)

        if not is_up:
            confirm = input(
                "[!] Host parece offline. Continuar mesmo assim? (s/n): ")
            if confirm.lower() != 's':
                return
        else:
            # Se encontramos uma interface específica, configuramos o Scapy para usá-la
            if found_iface:
                conf.iface = found_iface
                print(f"[*] Interface definida para o scan: {found_iface}")

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
