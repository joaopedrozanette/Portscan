import sys
import socket
import struct
import logging
import warnings
import ipaddress 

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, UDP, ICMP, sr1, conf, ARP, Ether, srp, get_if_list

conf.verb = 0

def resolve_target(target):
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
    target_str = str(target_obj)
    print(f"[*] Verificando se {target_str} está ativo...")

    
    if target_obj.is_loopback:
        return True, "lo"

    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) 
        
        result = s.connect_ex((target_str, 80)) 
        s.close()
        
        if result in [0, 111, 10061, 10035]: 
            print("[+] Host detectado via TCP Connect (Camada 4 - Roteável).")
            return True, None 
    except:
        pass

    interfaces = get_if_list()
    for iface in interfaces:
        if iface == 'lo': continue 
        try:
            my_ip_list = [x[4] for x in conf.route.routes if x[3] == iface and x[4] != '0.0.0.0']
            if not my_ip_list: continue
            my_ip = my_ip_list[0]

            arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_str, psrc=my_ip)
            ans, _ = srp(arp_pkt, timeout=0.5, verbose=0, iface=iface)
            if ans:
                print(f"[+] Host ativo detectado via ARP na interface {iface}.")
                return True, iface

            ping_pkt = IP(dst=target_str, src=my_ip)/ICMP()
            res = sr1(ping_pkt, timeout=1, verbose=0, iface=iface)
            if res:
                print(f"[+] Host ativo detectado via Ping na interface {iface}.")
                return True, iface
        except:
            continue

    return False, None



def syn_scan(target, port):
    """TCP SYN Scan"""
    try:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response is None: return "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "Open"
            elif response.getlayer(TCP).flags == 0x14: return "Closed"
        return "Unknown"
    except: return "Error"

def udp_scan(target, port):
    """UDP Scan"""
    try:
        packet = IP(dst=target)/UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=0)
        if response is None: return "Open | Filtered"
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3:
                if int(response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]: return "Filtered"
                elif int(response.getlayer(ICMP).code) == 3: return "Closed"
        return "Open"
    except: return "Error"

def ack_scan(target, port):
    try:
        packet = IP(dst=target)/TCP(dport=port, flags="A")
        response = sr1(packet, timeout=1, verbose=0)
        if response is None: return "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x04: return "Unfiltered"
        return "Filtered"
    except: return "Error"

def parse_ports(ports_input):
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
        except ValueError: pass
    return sorted(list(set(ports)))

def main():
    print("\n" + "="*25)
    print("   SCAPY PORT SCANNER ")
    print("="*25 + "\n")
    try:
        target_input = input("Digite o Alvo (IP ou Hostname): ")
        target_obj = resolve_target(target_input)
        is_up, found_iface = is_host_up(target_obj)
        if not is_up:
            confirm = input("[!] Host parece offline. Continuar? (s/n): ")
            if confirm.lower() != 's': return
        else:
            if found_iface and found_iface != 'lo':
                conf.iface = found_iface
        
        target_ip_str = str(target_obj)
        print(f"\n[*] Alvo definido: {target_ip_str}")
        print("1. TCP SYN \n2. UDP \n3. TCP ACK")
        choice = input("Selecione: ")
        ports = parse_ports(input("Portas: "))
        
        print("-" * 30)
        for port in ports:
            if choice == '1': res = syn_scan(target_ip_str, port)
            elif choice == '2': res = udp_scan(target_ip_str, port)
            elif choice == '3': res = ack_scan(target_ip_str, port)
            else: break
            print(f"{port:<10} {res:<15}")
    except KeyboardInterrupt: pass
    except Exception as e: print(e)

if __name__ == "__main__":
    main()
