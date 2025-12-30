# Port Scanner em Python (Scapy)

Implementação de um scanner de portas em Python utilizando **Scapy**, com suporte a diferentes tipos de varredura TCP e UDP, validação de alvos e tratamento de erros.

O projeto trabalha diretamente com pacotes de rede, permitindo observar como ferramentas como o **Nmap** operam em baixo nível, especialmente no envio e na interpretação de respostas de pacotes de rede.

---

## O que é um Port Scanner

Um port scanner é uma ferramenta utilizada para identificar quais portas de rede estão **abertas**, **fechadas** ou **filtradas** em um host.

Ele funciona enviando pacotes para portas específicas e analisando as respostas recebidas, o que permite inferir:

- Serviços em execução
- Regras de firewall
- Políticas de filtragem de rede
- Comportamento da pilha TCP/IP do sistema alvo

---

## Funcionalidades

- Validação de IPs e domínios
- Resolução DNS automática
- Identificação de alvos na rede local via ARP
- Suporte a múltiplos tipos de scan
- Escolha flexível de portas
- Tratamento completo de exceções
- Execução interativa via terminal

---

## Tipos de Scan Implementados

- **TCP SYN Scan**
  - Envia pacotes SYN
  - Identifica portas abertas sem completar o handshake TCP

- **TCP ACK Scan**
  - Utilizado para análise de regras de firewall
  - Identifica se uma porta está filtrada ou não

- **UDP Scan**
  - Envia pacotes UDP
  - Analisa respostas ICMP para inferir o estado da porta

- **Decoy Scan**
  - Utiliza IPs de origem falsos
  - Dificulta a identificação do verdadeiro originador do scan

---

## Tecnologias Utilizadas

- Python 3
- Scapy
- Socket
- ipaddress
- Protocolos TCP, UDP, ICMP e ARP

---

## Requisitos

- Sistema operacional Linux (recomendado)
- Python 3.9 ou superior
- Permissão de root (necessária para envio de pacotes raw)

> ⚠️ No Windows, o funcionamento é limitado devido às restrições no uso de raw sockets.

---

## Instalação

Clone o repositório:

```bash
git clone https://github.com/joaopedrozanette/Portscan.git
cd Portscan
