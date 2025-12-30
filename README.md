Port Scanner em Python (Scapy)

Implementação de um scanner de portas em Python utilizando Scapy, com suporte a diferentes tipos de varredura TCP e UDP, validação de alvos e tratamento de erros.

O projeto trabalha diretamente com pacotes de rede, permitindo observar como scanners como o Nmap funcionam em baixo nível.

O que é um Port Scanner

Um port scanner é uma ferramenta usada para identificar quais portas de rede estão abertas, fechadas ou filtradas em um host.
Ele funciona enviando pacotes para portas específicas e analisando as respostas recebidas, o que permite inferir:

Serviços em execução

Regras de firewall

Políticas de filtragem de rede

Funcionalidades

Validação de IPs e domínios

Resolução DNS automática

Detecção de alvo em LAN (ARP)

Múltiplos tipos de scan

Escolha flexível de portas

Tratamento de exceções e erros

Execução interativa via terminal

Tipos de Scan

TCP SYN Scan

Envia pacotes SYN

Não completa o handshake

Identifica portas abertas e fechadas

TCP ACK Scan

Utilizado para análise de firewall

Identifica portas filtradas ou não filtradas

UDP Scan

Envia pacotes UDP

Analisa respostas ICMP

Decoy Scan

Envia pacotes com IP de origem falso

Utilizado para mascarar a origem do scan

Tecnologias Utilizadas

Python 3

Scapy

Socket (stdlib)

ipaddress (stdlib)

Protocolos TCP, UDP, ICMP e ARP

Requisitos

Linux (recomendado)

Python 3.9+

Permissão de root (raw sockets)

⚠️ No Windows, o suporte é limitado devido a restrições de raw sockets.

Instalação

Clone o repositório:

git clone <url-do-repositorio>
cd Portscan


Instale a dependência:

pip install scapy


Opcional (ambiente virtual):

python3 -m venv venv
source venv/bin/activate

Execução

O script deve ser executado como root:

sudo python3 portscan.py


Durante a execução, o programa solicitará:

IP ou hostname do alvo

Tipo de scan

Portas a serem testadas

Exemplos de Uso

Scan em localhost:

127.0.0.1


Scan em host da rede:

192.168.1.10


Scan em domínio:

scanme.nmap.org

Tratamento de Erros

O código trata situações como:

IP inválido

Domínio inexistente ou malformado

Falha de resolução DNS

Interrupção do usuário (Ctrl + C)

Erros internos de envio de pacotes

As mensagens são exibidas de forma clara, sem stack trace desnecessário.

Análise de Pacotes

Durante a execução, é possível capturar os pacotes com ferramentas como Wireshark para observar:

Flags TCP (SYN, ACK, RST)

Respostas ICMP

Diferença entre portas abertas, fechadas e filtradas
