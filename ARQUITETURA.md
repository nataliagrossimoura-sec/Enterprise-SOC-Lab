# 🏗️ Arquitetura Detalhada - Enterprise SOC Lab

## 📐 Visão Geral da Arquitetura

O Enterprise SOC Lab implementa uma arquitetura de segurança em camadas, simulando um ambiente corporativo real com segregação de rede, monitoramento centralizado e coleta distribuída de logs.

---

## 🌐 Topologia de Rede

### Diagrama Lógico

```
┌─────────────────────────────────────────────────────────┐
│                    INTERNET (NAT)                       │
│                    10.0.2.0/24                          │
└─────────────────────┬───────────────────────────────────┘
                      │
                      │ WAN Interface
                      ↓
        ┌─────────────────────────────┐
        │       pfSense Firewall      │
        │       192.168.1.1/24        │
        │                             │
        │  - Firewall Rules           │
        │  - NAT                      │
        │  - DHCP Server              │
        │  - DNS Resolver             │
        └─────────────┬───────────────┘
                      │ LAN Interface
                      │ Internal Network: LAN_SOC
                      │ 192.168.1.0/24
                      │
        ┌─────────────┴───────────────────────────┐
        │                                         │
        │          INTERNAL LAN_SOC               │
        │          192.168.1.0/24                 │
        │                                         │
        └─┬────────┬────────┬────────┬───────────┘
          │        │        │        │
          ↓        ↓        ↓        ↓
    ┌─────────┐ ┌──────┐ ┌──────┐ ┌───────┐
    │  DC01   │ │Wazuh │ │Ubuntu│ │ Kali  │
    │.51      │ │.102  │ │ Lab  │ │ .10   │
    │         │ │      │ │ .101 │ │       │
    │Windows  │ │Ubuntu│ │Ubuntu│ │Kali   │
    │Server   │ │Server│ │      │ │Linux  │
    └─────────┘ └──────┘ └──────┘ └───────┘
```

### Segmentação de Rede

| Segmento | Range | Propósito | Gateway |
|----------|-------|-----------|---------|
| **WAN** | 10.0.2.0/24 | Conexão externa (NAT) | VirtualBox NAT |
| **LAN_SOC** | 192.168.1.0/24 | Rede interna do laboratório | 192.168.1.1 |

**Observação:** A rede é completamente isolada usando **Internal Network** do VirtualBox. Não há ponte (bridge) com a rede física do host.

---

## 🖥️ Inventário Detalhado de Hosts

### 1. pfSense - Firewall e Gateway

**Especificações Técnicas:**
- **Sistema Operacional:** pfSense CE (FreeBSD-based)
- **vCPU:** 1 core
- **RAM:** 1 GB
- **Disco:** 10 GB
- **Interfaces:**
  - **em0 (WAN):** Adaptador NAT → 10.0.2.15/24
  - **em1 (LAN):** Internal Network → 192.168.1.1/24

**Funções:**
- Roteamento entre WAN e LAN
- Firewall corporativo
- DHCP Server (Range: 192.168.1.10 - 192.168.1.200)
- DNS Resolver (cache local)
- NAT para acesso à internet

**Regras de Firewall:**
```
LAN → ANY: ALLOW (saída permitida)
WAN → LAN: BLOCK (entrada bloqueada)
Anti-Lockout Rule: ALLOW (acesso web admin)
```

**Portas de Gerenciamento:**
- Web Interface: `http://192.168.1.1:80`
- SSH: `22` (desabilitado por padrão)

---

### 2. Windows Server (DC01) - Servidor de Logs e SIEM

**Especificações Técnicas:**
- **Sistema Operacional:** Windows Server 2022 (Desktop Experience)
- **vCPU:** 2 cores
- **RAM:** 4-6 GB
- **Disco:** 60 GB
- **Interface:** Internal Network → LAN_SOC
- **IP:** 192.168.1.51/24 (DHCP ou estático)
- **Gateway:** 192.168.1.1
- **DNS:** 192.168.1.1

**Funções:**
- Active Directory Domain Services (opcional)
- Servidor Splunk Enterprise
- Coleta de telemetria avançada (Sysmon)
- Endpoint monitorado (Wazuh Agent)
- Servidor de logs Windows

**Serviços Instalados:**

| Serviço | Porta | Função |
|---------|-------|--------|
| Splunk Enterprise | 8000 (HTTPS) | Web Interface |
| Splunk Indexer | 9997 | Recebimento de logs |
| Wazuh Agent | 1514 (outbound) | Envio de logs ao Manager |
| Sysmon | N/A | Telemetria de sistema |
| RDP | 3389 | Acesso remoto |

**Logs Coletados:**
- Windows Security Events (Event ID 4624, 4625, 4688, etc.)
- Sysmon Operational Logs (Event ID 1, 3, 7, 11, 13, etc.)
- System Events
- Application Events
- PowerShell Logs

**Ferramentas Adicionais:**
- Wireshark (análise de pacotes)
- Gawk (processamento de texto)
- Event Viewer (visualização de logs)

---

### 3. Ubuntu Wazuh Server - SIEM Central

**Especificações Técnicas:**
- **Sistema Operacional:** Ubuntu Server 22.04 LTS
- **Hostname:** wazuh-server
- **vCPU:** 2 cores
- **RAM:** 4 GB
- **Disco:** 40 GB
- **Interface:** Internal Network → LAN_SOC
- **IP:** 192.168.1.102/24
- **Gateway:** 192.168.1.1

**Funções:**
- Wazuh Manager (central de gerenciamento)
- Wazuh Indexer (armazenamento de eventos)
- Wazuh Dashboard (interface web)
- API REST (automação)

**Componentes da Stack Wazuh:**

```
┌─────────────────────────────────────┐
│        Wazuh Dashboard              │
│        (Kibana customizado)         │
│        Port: 443                    │
└────────────┬────────────────────────┘
             │
             ↓
┌─────────────────────────────────────┐
│        Wazuh Indexer                │
│        (OpenSearch)                 │
│        Port: 9200                   │
└────────────┬────────────────────────┘
             │
             ↓
┌─────────────────────────────────────┐
│        Wazuh Manager                │
│        Port: 1514, 1515, 55000      │
│                                     │
│  - Recebe logs dos agents           │
│  - Processa regras de detecção      │
│  - Correlaciona eventos             │
│  - Gera alertas                     │
└─────────────────────────────────────┘
```

**Portas Utilizadas:**

| Porta | Protocolo | Função |
|-------|-----------|--------|
| 443 | HTTPS | Wazuh Dashboard |
| 1514 | TCP | Recebimento de logs (agents) |
| 1515 | TCP | Registro de agents |
| 55000 | TCP | API REST |
| 9200 | TCP | Wazuh Indexer |

**Credenciais Salvas:**
- Elasticsearch: `lw+NTGZN6tK5hH8c5Ff9`
- Kibana: `MkC1f60-FcN3qdLPxSx0`

**Acesso Web:** `https://192.168.1.102`

---

### 4. Ubuntu Lab - Endpoint Linux Monitorado

**Especificações Técnicas:**
- **Sistema Operacional:** Ubuntu Desktop 22.04 LTS
- **Hostname:** ubuntu-lab
- **vCPU:** 1 core
- **RAM:** 2 GB
- **Disco:** 20 GB
- **Interface:** Internal Network → LAN_SOC
- **IP:** 192.168.1.101/24 (DHCP)
- **Gateway:** 192.168.1.1

**Funções:**
- Endpoint Linux generalista
- Wazuh Agent ativo
- Desenvolvimento de scripts
- Análise e testes

**Ferramentas Instaladas:**
- Wazuh Agent
- tcpdump (captura de pacotes)
- net-tools (utilitários de rede)
- htop (monitor de processos)
- vim/nano (editores de texto)

**Logs Coletados:**
- /var/log/syslog
- /var/log/auth.log
- /var/log/kern.log
- Logs de aplicações

---

### 5. Kali Linux - Red Team / Pentest

**Especificações Técnicas:**
- **Sistema Operacional:** Kali Linux 2024.x
- **Hostname:** kali
- **vCPU:** 1-2 cores
- **RAM:** 2 GB
- **Disco:** 20-30 GB
- **Interface:** Internal Network → LAN_SOC
- **IP:** 192.168.1.10/24 (DHCP)
- **Gateway:** 192.168.1.1

**Funções:**
- Simulação de ataques controlados
- Testes de segurança
- Geração de tráfego suspeito
- Validação de detecções

**Ferramentas Principais:**
- Nmap (escaneamento de rede)
- Metasploit Framework (exploração)
- Hydra (brute force)
- Burp Suite (teste de aplicações web)
- SQLMap (injeção SQL)
- Nikto (scanner web)
- John the Ripper (quebra de senhas)
- Wireshark (análise de pacotes)

**Observação Importante:** Esta VM **NÃO possui agente Wazuh** por decisão de design, para simular um atacante externo sem monitoramento.

---

## 🔄 Fluxo de Dados

### Pipeline de Coleta de Logs

```
┌───────────────────────────────────────────────────────────────┐
│                    COLETA DE EVENTOS                          │
└───────────────────────────────────────────────────────────────┘
                              │
                              ↓
        ┌─────────────────────────────────────┐
        │   ENDPOINTS MONITORADOS             │
        ├─────────────────────────────────────┤
        │  • Windows DC01 (Sysmon + Events)   │
        │  • Ubuntu Lab (Syslog + Auth)       │
        └─────────────┬───────────────────────┘
                      │
                      │ Wazuh Agents
                      │ (TLS encrypted)
                      ↓
        ┌─────────────────────────────────────┐
        │      WAZUH MANAGER                  │
        │      192.168.1.102:1514             │
        ├─────────────────────────────────────┤
        │  • Recebe logs                      │
        │  • Decodifica eventos               │
        │  • Aplica regras de detecção        │
        │  • Correlaciona eventos             │
        │  • Gera alertas                     │
        └─────────────┬───────────────────────┘
                      │
                      ↓
        ┌─────────────────────────────────────┐
        │      WAZUH INDEXER                  │
        │      (OpenSearch)                   │
        ├─────────────────────────────────────┤
        │  • Armazena eventos                 │
        │  • Indexação para busca rápida      │
        │  • Retenção configurável            │
        └─────────────┬───────────────────────┘
                      │
                      ↓
        ┌─────────────────────────────────────┐
        │      WAZUH DASHBOARD                │
        │      https://192.168.1.102          │
        ├─────────────────────────────────────┤
        │  • Visualização de eventos          │
        │  • Dashboards interativos           │
        │  • Investigação de incidentes       │
        │  • Relatórios                       │
        └─────────────────────────────────────┘
```

### Fluxo Paralelo - Splunk

```
┌───────────────────────────────────────┐
│   Windows DC01 (Logs Windows)         │
└───────────────┬───────────────────────┘
                │
                │ Splunk Universal Forwarder
                │ (Port 9997)
                ↓
┌───────────────────────────────────────┐
│   SPLUNK ENTERPRISE                   │
│   192.168.1.51:8000                   │
├───────────────────────────────────────┤
│  • Indexação de logs                  │
│  • Search Processing Language (SPL)   │
│  • Dashboards customizados            │
│  • Alertas configurados               │
└───────────────────────────────────────┘
```

---

## 🛡️ Camadas de Segurança

### 1. Perímetro (Firewall)

**Componente:** pfSense  
**Função:** Controle de tráfego entre WAN e LAN

**Proteções:**
- Filtragem stateful
- Bloqueio de tráfego não solicitado da WAN
- Proteção contra port scanning
- Logs de firewall

### 2. Endpoint (Hosts)

**Componentes:** DC01, Ubuntu Lab

**Proteções:**
- Agentes Wazuh ativos
- Sysmon (Windows)
- Auditoria detalhada de eventos
- Hardening de serviços

### 3. SIEM (Detecção e Resposta)

**Componentes:** Wazuh Manager, Splunk

**Capacidades:**
- Detecção baseada em regras
- Correlação de eventos
- Análise comportamental
- Alertas em tempo real
- Integração com MITRE ATT&CK

---

## 🔍 Tipos de Eventos Monitorados

### Windows (DC01)

| Categoria | Event IDs | Descrição |
|-----------|-----------|-----------|
| **Autenticação** | 4624, 4625 | Logon sucesso/falha |
| **Processos** | 4688 | Criação de processo |
| **Sysmon - Processo** | 1 | Process creation |
| **Sysmon - Rede** | 3 | Network connection |
| **Sysmon - DLL** | 7 | Image/DLL loaded |
| **Sysmon - Arquivo** | 11 | File created |
| **Sysmon - Registry** | 13 | Registry value set |
| **PowerShell** | 4103, 4104 | Script block logging |

### Linux (Ubuntu Lab)

| Categoria | Log File | Descrição |
|-----------|----------|-----------|
| **Autenticação** | /var/log/auth.log | SSH, sudo, login |
| **Sistema** | /var/log/syslog | Mensagens gerais |
| **Kernel** | /var/log/kern.log | Kernel messages |
| **Aplicações** | /var/log/*.log | Logs diversos |

### Rede (pfSense)

| Categoria | Descrição |
|-----------|-----------|
| **Firewall** | Pacotes bloqueados/permitidos |
| **DHCP** | Atribuições de IP |
| **DNS** | Consultas DNS |

---

## 📊 Mapeamento MITRE ATT&CK

### Técnicas Detectáveis no Lab

| Tática | Técnica | ID | Detecção |
|--------|---------|----|---------| 
| **Initial Access** | Brute Force | T1110 | Event ID 4625 múltiplo |
| **Execution** | PowerShell | T1059.001 | Sysmon Event 1 + Rule 80100 |
| **Persistence** | Registry Run Keys | T1547 | Sysmon Event 13 |
| **Discovery** | Network Scanning | T1046 | pfSense + Wazuh correlation |
| **Lateral Movement** | Remote Services | T1021 | Event ID 4624 Type 3 |
| **Command & Control** | Reverse Shell | T1071 | Sysmon Event 3 (unusual port) |

---

## 🔧 Requisitos de Hardware Consolidados

### Por VM

| VM | vCPU | RAM | Disco | Adaptador |
|----|------|-----|-------|-----------|
| pfSense | 1 | 1 GB | 10 GB | NAT + Internal |
| DC01 | 2 | 4-6 GB | 60 GB | Internal |
| Wazuh Server | 2 | 4 GB | 40 GB | Internal |
| Ubuntu Lab | 1 | 2 GB | 20 GB | Internal |
| Kali Linux | 1-2 | 2 GB | 20-30 GB | Internal |
| **TOTAL** | **7-8** | **13-15 GB** | **150-180 GB** | - |

### Host Físico Recomendado

- **CPU:** Intel i5/i7 (8+ threads)
- **RAM:** 24-32 GB
- **SSD:** 500 GB - 1 TB
- **Rede:** Ethernet 1 Gbps

---

## 🚀 Escalabilidade Futura

### Possíveis Expansões

1. **Adicionar Suricata IDS**
   - Detecção de intrusão de rede
   - Integração com Wazuh

2. **Implementar TheHive**
   - Case management
   - Resposta a incidentes

3. **Adicionar MISP**
   - Threat intelligence
   - Compartilhamento de IOCs

4. **Deploy de Honeypots**
   - Cowrie (SSH honeypot)
   - Dionaea (multiprotocol)

5. **Implementar SOAR**
   - Shuffle ou Cortex
   - Automação de resposta

---

## 📝 Considerações de Design

### Decisões Arquiteturais

**Por que Internal Network?**
- Isolamento total da rede física
- Segurança do host
- Evita exposição acidental

**Por que Kali sem agente Wazuh?**
- Simula atacante externo
- Não possui visibilidade do SOC
- Testes mais realistas

**Por que Splunk e Wazuh juntos?**
- Splunk: Análise profunda com SPL
- Wazuh: Detecção em tempo real
- Complementaridade de ferramentas

**Por que pfSense?**
- Firewall corporativo real
- Recursos avançados gratuitos
- Amplamente usado em empresas

---

## 🔐 Princípios de Segurança

1. **Defense in Depth:** Múltiplas camadas de proteção
2. **Least Privilege:** Serviços com permissões mínimas
3. **Monitoring:** Tudo é logado e correlacionado
4. **Isolation:** Rede completamente isolada
5. **Hardening:** Configurações seguras em todos componentes

---

## 📌 Conclusão

Esta arquitetura foi projetada para:
- ✅ Simular ambiente corporativo real
- ✅ Demonstrar competências SOC
- ✅ Praticar detecção e resposta
- ✅ Ser escalável e expansível
- ✅ Documentar procedimentos operacionais

A topologia permite crescimento futuro sem reestruturação significativa, mantendo os princípios de segurança e isolamento.
