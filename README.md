🎯 Objetivos do Projeto

Implementar um scanner de portas funcional em Python

Trabalhar diretamente com pacotes TCP e UDP

Compreender como diferentes tipos de scan funcionam

Analisar respostas de rede para determinar o estado das portas

Aplicar validação rigorosa de entrada (IPs e domínios)

Utilizar técnicas reais de varredura de portas

Produzir um código organizado, legível e robusto

🧠 Funcionamento Geral

O scanner segue o fluxo abaixo:

O usuário informa um IP ou hostname

A entrada é validada para garantir que seja:

Um IP válido

Um domínio válido

Caso seja um domínio, ocorre a resolução DNS

O scanner tenta resolver o endereço MAC via ARP quando o alvo está na mesma rede local

O usuário escolhe:

O tipo de scan

O conjunto de portas a ser testado

Pacotes são enviados ao alvo

As respostas recebidas são analisadas

O estado de cada porta é exibido ao usuário

🌐 Tipos de Scan Implementados
TCP SYN Scan

Envia pacotes TCP com a flag SYN

Não completa o handshake TCP

Utilizado para identificar portas abertas de forma discreta

Interpretação:

SYN + ACK → Porta aberta

RST → Porta fechada

Sem resposta → Porta filtrada

TCP ACK Scan

Envia pacotes TCP com a flag ACK

Não identifica serviços

Utilizado para mapear regras de firewall

Interpretação:

RST → Porta não filtrada

Sem resposta → Porta filtrada

UDP Scan

Envia pacotes UDP para as portas alvo

Analisa respostas ICMP

Interpretação:

ICMP Type 3 → Porta fechada

Sem resposta → Open | Filtered

Decoy Scan

Envia pacotes com IP de origem falso

Utilizado para confundir logs e mecanismos de detecção

Implementado com finalidade de estudo e compreensão da técnica

📦 Tecnologias Utilizadas

Python 3

Scapy

Socket (biblioteca padrão)

ipaddress (biblioteca padrão)

ARP, TCP, UDP, ICMP (protocolos de rede)

⚙️ Requisitos
Sistema Operacional

Linux (recomendado)

Windows possui suporte limitado para raw sockets

Permissões

O script deve ser executado como root (ou com sudo), pois utiliza raw sockets

Dependências

Python 3.9 ou superior

Scapy

📥 Instalação
1️⃣ Clonar o repositório
git clone <url-do-repositorio>
cd Portscan

2️⃣ Criar ambiente virtual (opcional, mas recomendado)
python3 -m venv venv
source venv/bin/activate

3️⃣ Instalar dependências
pip install scapy

4️⃣ Verificar instalação do Scapy
python3 -c "from scapy.all import *; print('Scapy OK')"

▶️ Execução

Execute o script com privilégios de administrador:

sudo python3 portscan.py


O programa apresentará um menu interativo solicitando:

Alvo (IP ou hostname)

Tipo de scan

Portas a serem testadas

🧪 Exemplos de Teste

Scan em localhost:

127.0.0.1


Scan em host da rede local:

192.168.1.10


Scan em domínio:

scanme.nmap.org

📊 Análise de Pacotes com Wireshark

Durante a execução do scanner, é possível capturar os pacotes utilizando o Wireshark para observar:

Flags TCP (SYN, ACK, RST)

Respostas ICMP

Diferença entre portas abertas, fechadas e filtradas

Filtros úteis:

tcp
udp
icmp


ou:

tcp.port == 80

⚠️ Tratamento de Erros e Exceções

O código possui tratamento para:

Interrupção pelo usuário (Ctrl + C)

IP inválido

Domínio malformado ou inexistente

Erros de resolução DNS

Erros internos do Scapy

O objetivo é evitar a exposição de stack traces e fornecer mensagens claras ao usuário.

🔒 Considerações de Segurança

Utilize o scanner apenas em ambientes controlados

Nunca execute scans sem autorização

O uso indevido pode violar políticas de segurança e legislação vigente

📌 Conclusão

Este projeto demonstra, de forma prática, como scanners de portas funcionam em baixo nível, abordando conceitos fundamentais de redes, protocolos e análise de pacotes. Ele serve como uma base sólida para aprofundamento em áreas como segurança de redes, pentest, monitoramento e engenharia de redes.
