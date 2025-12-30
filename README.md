# Port Scanner em Python (Scapy)

Implementação de um scanner de portas em Python utilizando **Scapy**, com suporte a diferentes tipos de varredura TCP e UDP, validação de alvos e tratamento de erros.

O projeto trabalha diretamente com pacotes de rede em baixo nível, permitindo observar como ferramentas como o **Nmap** operam internamente, especialmente no envio de pacotes e na interpretação das respostas da pilha TCP/IP.

---

## O que é um Port Scanner

Um port scanner é uma ferramenta utilizada para identificar quais portas de rede estão **abertas**, **fechadas** ou **filtradas** em um host.

Ele funciona enviando pacotes para portas específicas e analisando as respostas recebidas, o que permite inferir:

- Serviços em execução
- Presença e comportamento de firewalls
- Políticas de filtragem de rede
- Respostas da pilha TCP/IP do sistema alvo

---

## Funcionalidades

- Validação de endereços IP e nomes de domínio
- Resolução DNS automática
- Suporte a múltiplos tipos de scan TCP e UDP
- Seleção flexível de portas para varredura
- Uso direto de pacotes raw com Scapy
- Tratamento de exceções e interrupções
- Execução interativa via terminal

---

## Tipos de Scan Implementados

### TCP SYN Scan
- Envia pacotes TCP com a flag **SYN**
- Identifica portas abertas sem completar o handshake TCP
- Baseado no comportamento padrão da pilha TCP/IP

### TCP ACK Scan
- Envia pacotes TCP com a flag **ACK**
- Utilizado para análise de filtragem por firewall
- Diferencia portas **filtered** e **unfiltered**
- Não determina se a porta está aberta ou fechada

### UDP Scan
- Envia pacotes UDP para as portas alvo
- Analisa respostas ICMP para inferir o estado da porta
- Estados possíveis: **open**, **closed**, **filtered** ou **open|filtered**

### Decoy Scan
- Envia múltiplos pacotes SYN com IPs de origem falsificados
- Dificulta a identificação do verdadeiro originador do scan
- Realiza um envio real para análise da resposta da porta

---

## Tecnologias Utilizadas

- Python 3
- Scapy
- Socket
- ipaddress
- Protocolos TCP, UDP e ICMP

---

## Requisitos

- Sistema operacional Linux (recomendado)
- Python 3.9 ou superior
- Permissão de root (necessária para envio de pacotes raw)

> ⚠️ Em sistemas Windows, o funcionamento é limitado devido às restrições no uso de raw sockets.

---

## Instalação

Clone o repositório:

```bash
git clone https://github.com/joaopedrozanette/Portscan.git
cd Portscan


## Instalação

##Instale a dependência principal:


pip install scapy

##Execução do Script:

sudo python3 portscan.py


