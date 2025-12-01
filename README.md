# Enterprise-SOC-Lab
Laboratório de segurança corporativa simulada: firewall pfSense, coleta centralizada de logs, SIEM (Wazuh/Splunk), análise de eventos Windows e Linux, regras de detecção e resposta a incidentes

# 🛡️ Enterprise SOC Lab

## 📋 Sobre o Projeto
Este laboratório simula um ambiente corporativo de Segurança Operacional (SOC).
O objetivo é demonstrar, passo a passo, como coletar logs, detectar ameaças, investigar alertas e responder a incidentes em um cenário realista.

# 🛡️ Enterprise SOC Lab

![Status](https://img.shields.io/badge/Status-Active-success)
![Platform](https://img.shields.io/badge/Platform-VirtualBox-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen)

**Autora:** Natália Grossi  
**Projeto:** Laboratório SOC Corporativo Completo  
**Data:** Novembro 2025

---

## 📋 Visão Geral

O **Enterprise SOC Lab** é um ambiente corporativo completo de Segurança da Informação, desenvolvido para simular uma infraestrutura real de empresa com:

- ✅ Monitoramento centralizado de segurança (SIEM)
- ✅ Detecção de ameaças em tempo real
- ✅ Análise forense de eventos
- ✅ Resposta a incidentes
- ✅ Simulação de ataques controlados
- ✅ Telemetria avançada de endpoints
- ✅ Correlação de eventos Windows/Linux/Rede

Este laboratório demonstra competências práticas de **Analista SOC**, **Blue Team** e **DFIR (Digital Forensics and Incident Response)**.

---

## 🎯 Objetivos do Projeto

1. Construir infraestrutura SOC corporativa do zero
2. Implementar SIEM com Wazuh e Splunk
3. Configurar telemetria avançada com Sysmon
4. Estabelecer coleta centralizada de logs
5. Criar regras de detecção base MITRE ATT&CK
6. Simular ataques e validar defesas
7. Desenvolver habilidades de investigação forense
8. Documentar procedimentos operacionais

---

## 🏗️ Arquitetura da Rede

### Topologia Completa

```
                    INTERNET (NAT)
                          |
                    [pfSense FW]
                    192.168.1.1
                          |
        ┌─────────────────┼─────────────────┐
        |                 |                 |
   [Windows DC01]    [Wazuh Server]   [Ubuntu Lab]
   192.168.1.51      192.168.1.102    192.168.1.101
   SIEM + Sysmon     Manager/Index    Linux Agent
        |                 |                 |
        └─────────────────┼─────────────────┘
                          |
                    [Kali Linux]
                    192.168.1.10
                    Red Team
```

### Inventário Completo

| Máquina | Função | IP | SO | Agentes/Serviços |
|---------|--------|----|----|------------------|
| **pfSense** | Firewall + Gateway + DHCP | 192.168.1.1 | FreeBSD | Firewall, NAT, DNS |
| **DC01** | AD + SIEM + Logs | 192.168.1.51 | Windows Server 2022 | Splunk, Sysmon, Wazuh Agent |
| **Wazuh Server** | SIEM Central | 192.168.1.102 | Ubuntu Server | Manager, Indexer, Dashboard |
| **Ubuntu Lab** | Endpoint Linux | 192.168.1.101 | Ubuntu Desktop | Wazuh Agent, Scripts |
| **Kali Linux** | Pentest/Red Team | 192.168.1.10 | Kali Linux | Ferramentas de ataque |

**Rede Interna:** `192.168.1.0/24` (LAN_SOC)  
**Gateway Padrão:** `192.168.1.1` (pfSense)  
**DNS:** `192.168.1.1`

---

## 🛠️ Ferramentas e Tecnologias

### SIEM e Monitoramento
- **Wazuh 4.x** - Plataforma XDR/SIEM open-source
- **Splunk Enterprise** - Análise de logs corporativa
- **Sysmon** - Telemetria avançada Windows
- **Windows Event Viewer** - Logs nativos do sistema

### Análise de Rede
- **pfSense** - Firewall corporativo
- **Wireshark** - Análise de pacotes
- **tcpdump** - Captura de tráfego

### Ferramentas de Análise
- **PowerShell** - Automação Windows
- **Bash** - Scripts Linux
- **awk/sed/grep** - Processamento de logs
- **Gawk** - Análise avançada de texto

### Red Team
- **Kali Linux** - Distribuição de pentest
- **Nmap** - Escaneamento de rede
- **Metasploit** - Framework de exploração
- **Hydra** - Brute force

---

## 📦 Pré-requisitos

### Hardware Mínimo
- **CPU:** Intel i3 (4 threads) ou superior
- **RAM:** 16 GB (24-32 GB recomendado)
- **Armazenamento:** 300 GB SSD
- **Rede:** Conexão Ethernet estável

### Software
- Windows 10/11 atualizado
- VirtualBox 7.0+ ou VMware Workstation
- ISOs necessárias:
  - pfSense CE
  - Windows Server 2022
  - Ubuntu Server LTS
  - Ubuntu Desktop LTS
  - Kali Linux

### Conhecimentos Recomendados
- Redes TCP/IP básico
- Conceitos de SIEM
- Windows Server básico
- Linux básico
- PowerShell/Bash intermediário

---

## 🚀 Guia de Instalação

### Instalação Rápida (Resumo)

1. **Preparar Ambiente Host**
   ```bash
   # Criar estrutura de pastas
   mkdir C:\SOC-Lab\{VMs,ISOs,Snapshots,Configs,Scripts,Logs,Docs}
   ```

2. **Configurar VirtualBox**
   - Criar rede interna: `LAN_SOC`
   - Configurar Host-Only Network (se necessário)

3. **Instalar VMs na Sequência**
   - pfSense (Firewall)
   - Windows Server (DC01)
   - Ubuntu Wazuh Server
   - Ubuntu Lab
   - Kali Linux

4. **Configurar Serviços**
   - Wazuh Stack completo
   - Splunk Enterprise
   - Sysmon com configuração reforçada
   - Agentes Wazuh em todos endpoints

5. **Validar Conectividade**
   ```powershell
   # Windows
   Test-NetConnection 192.168.1.1
   ```
   ```bash
   # Linux
   ping -c 4 192.168.1.1
   ```

### Documentação Completa

Para guia passo a passo detalhado, consulte:
- 📖 **[INSTALLATION.md](INSTALLATION.md)** - Guia completo de instalação
- 🏗️ **[ARCHITECTURE.md](ARCHITECTURE.md)** - Detalhes da arquitetura
- 📁 **[docs/](docs/)** - Documentação técnica por componente

---

## 📊 Fluxo de Dados e Segurança

### Pipeline de Logs

```
[Endpoints] → [Agents] → [Wazuh Manager] → [Indexer] → [Dashboard]
     ↓           ↓             ↓                ↓            ↓
  Sysmon     Wazuh Agent   Correlação      Elastic      Kibana
  Event Log   File Beat    Detecção        Storage      Análise
     ↓           ↓             ↓                ↓            ↓
[Splunk Forwarder] → [Splunk Server] → [Análise Profunda]
```

### Casos de Uso Implementados

1. **Execução de PowerShell Malicioso**
   - Detectado via: Sysmon Event ID 1
   - Alerta: Wazuh Rule 80100
   - Correlação: Splunk Search

2. **Port Scan de Rede**
   - Origem: Kali Linux (Nmap)
   - Detectado: pfSense + Wazuh
   - Classificação: MITRE T1046

3. **Brute Force Attack**
   - Ferramenta: Hydra
   - Detectado: Event ID 4625 (Windows)
   - Alerta: Múltiplas falhas de autenticação

4. **Download Suspeito**
   - Detectado: Sysmon Event ID 3 (Network Connection)
   - Análise: Conexão a IP externo não autorizado

5. **Persistence via Registry**
   - Detectado: Sysmon Event ID 13 (Registry Value Set)
   - MITRE: T1547 (Boot or Logon Autostart)

---

## 💻 Comandos Essenciais

### Linux (Ubuntu Lab)

```bash
# Verificar status Wazuh Agent
sudo systemctl status wazuh-agent

# Monitorar logs em tempo real
tail -f /var/ossec/logs/ossec.log

# Capturar tráfego de rede
sudo tcpdump -i enp0s3 -nn -w capture.pcap

# Análise de logs com awk
awk '{print $1, $4}' /var/log/syslog | sort | uniq -c

# Buscar padrões com grep
grep -i "failed" /var/log/auth.log | wc -l
```

### PowerShell (Windows DC01)

```powershell
# Ver últimos eventos de segurança
Get-EventLog -LogName Security -Newest 50

# Logs do Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100

# Verificar agente Wazuh
Get-Service -Name wazuh | Select-Object Status, StartType

# Processos suspeitos
Get-Process | Where-Object {$_.Path -like "*temp*"} | Select-Object Name, Path, Id

# Exportar logs para análise
Get-EventLog -LogName Security -After (Get-Date).AddDays(-1) | 
    Export-Csv C:\Logs\security-last24h.csv -NoTypeInformation
```

### Splunk Queries

```spl
# Buscar eventos Sysmon
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

# Detectar PowerShell suspeito
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"

# Conexões de rede externas
index=sysmon EventCode=3 DestinationIp!=192.168.*

# Top 10 processos criados
index=sysmon EventCode=1 | stats count by Image | sort -count | head 10
```

Para lista completa: **[COMMANDS_USED.md](COMMANDS_USED.md)**

---

## 📁 Estrutura do Repositório

```
Enterprise-SOC-Lab/
│
├── README.md                    # Este arquivo
├── ARCHITECTURE.md              # Detalhes da arquitetura
├── INSTALLATION.md              # Guia de instalação completo
├── COMMANDS_USED.md             # Comandos Linux e PowerShell
├── LOGS_AND_MONITORING.md       # Logs coletados e análise
├── TROUBLESHOOTING.md           # Solução de problemas
├── LICENSE                      # Licença MIT
│
├── docs/                        # Documentação detalhada
│   ├── 01-pre-requisitos.md
│   ├── 02-preparacao-host.md
│   ├── ...
│   └── 12-recursos-adicionais.md
│
├── diagrams/                    # Diagramas de rede e fluxos
│   ├── network-diagram.png
│   ├── network-diagram.drawio
│   └── soc-workflow.png
│
├── screenshots/                 # Evidências visuais
│   ├── wazuh/
│   ├── splunk/
│   ├── windows/
│   ├── network/
│   └── kali/
│
├── configs/                     # Arquivos de configuração
│   ├── sysmon-config.xml
│   ├── wazuh-agent.conf
│   └── splunk-inputs.conf
│
├── scripts/                     # Scripts de automação
│   ├── windows/
│   ├── linux/
│   └── README.md
│
└── logs/                        # Amostras de logs
    ├── samples/
    └── README.md
```

---

## 🔍 Análise e Detecção

### Regras Wazuh Personalizadas

Exemplo de detecção de PowerShell suspeito:

```xml
<rule id="80100" level="8">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image">.*powershell.exe</field>
  <field name="win.eventdata.commandLine">.*-enc.*</field>
  <description>PowerShell com comando codificado detectado</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

### Dashboard Wazuh

Principais visualizações:
- Agentes conectados em tempo real
- Top 10 alertas de segurança
- Eventos por severidade
- Geolocalização de IPs
- Timeline de ataques

### Dashboard Splunk

Métricas monitoradas:
- Volume de logs por host
- Eventos de autenticação
- Atividade de processos
- Tráfego de rede anômalo
- Erros e warnings críticos

---

## 🧪 Exercícios Práticos

### Exercício 1: Simular Port Scan
```bash
# No Kali Linux
nmap -sS -p- 192.168.1.51

# Detectar no Wazuh Dashboard
# Verificar alertas: "Network scan detected"
```

### Exercício 2: Brute Force SMB
```bash
# No Kali Linux
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.1.51

# Verificar Event ID 4625 no DC01
# Alerta Wazuh: Multiple authentication failures
```

### Exercício 3: Detectar PowerShell Suspeito
```powershell
# No Windows DC01 (como admin)
powershell -enc <base64_encoded_command>

# Sysmon Event ID 1 gerado
# Wazuh Rule 80100 ativada
# Buscar no Splunk: index=sysmon EventCode=1 CommandLine="*-enc*"
```

Ver todos: **[docs/11-exercicios-praticos.md](docs/11-exercicios-praticos.md)**

---

## 🛡️ Segurança do Laboratório

### Princípios de Isolamento

✅ **Rede 100% isolada** - Somente Internal Network  
✅ **Sem Bridge Mode** - Não expor para rede física  
✅ **Snapshots regulares** - Backup antes de mudanças  
✅ **Senhas fortes** - Todas as VMs protegidas  
✅ **Firewall configurado** - pfSense com regras restritivas  
✅ **Ataques controlados** - Somente dentro da LAN_SOC

### Hardening Aplicado

- Desativação de serviços desnecessários
- Auditoria detalhada habilitada (auditpol)
- Sysmon com configuração reforçada
- Wazuh com regras de detecção ativas
- Logs centralizados e correlacionados

---

## 📚 Recursos Adicionais

### Documentação Oficial
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Splunk Docs](https://docs.splunk.com/)
- [Sysmon Documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [pfSense Documentation](https://docs.netgate.com/pfsense/)

### Frameworks de Segurança
- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

### Comunidades
- [r/cybersecurity](https://reddit.com/r/cybersecurity)
- [SANS Reading Room](https://www.sans.org/reading-room/)
- [Wazuh Community](https://wazuh.com/community/)

---

## 🔄 Roadmap Futuro

### Próximas Implementações

- [ ] Integração com MISP (Threat Intelligence)
- [ ] TheHive para case management
- [ ] Elastic Fleet Server
- [ ] Automação com SOAR (Shuffle)
- [ ] Honeypots (Cowrie, Dionaea)
- [ ] EDR adicional (Velociraptor)
- [ ] Network IDS (Suricata)
- [ ] Log forwarding para ELK Stack

---

## 🎓 Aprendizados e Competências

### Competências Técnicas Demonstradas

✅ Arquitetura de Segurança  
✅ Administração Windows Server  
✅ Administração Linux  
✅ Redes TCP/IP e Firewall  
✅ SIEM (Wazuh + Splunk)  
✅ Telemetria de Endpoints (Sysmon)  
✅ Análise de Logs  
✅ Detecção de Ameaças  
✅ Resposta a Incidentes  
✅ MITRE ATT&CK Framework  
✅ PowerShell/Bash Scripting  
✅ Packet Analysis  
✅ Virtualização  
✅ Documentação Técnica  

---

## 👤 Sobre a Autora

**Natália Grossi**  
Analista de Cibersegurança | SOC | Blue Team

Apaixonada por segurança defensiva, detecção de ameaças e análise forense. Este laboratório representa minha jornada de transição para Cibersegurança, demonstrando habilidades práticas e conhecimento teórico aplicado.

📧 **Contato:**  
- LinkedIn: [seu-perfil-linkedin]  
- GitHub: [@seu-usuario]  
- Email: seu.email@example.com

---

## 📝 Licença

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🙏 Agradecimentos

- Comunidade Wazuh pelo suporte
- Documentação Splunk
- Microsoft Sysinternals Team
- Comunidade de Cibersegurança brasileira

---

## 📞 Contribuições

Sugestões e melhorias são bem-vindas!

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

<div align="center">

**⭐ Se este projeto foi útil, considere dar uma estrela!**

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=seu-usuario.enterprise-soc-lab)

**Última atualização:** Novembro 2025
**Status:** 🟢 Ativo e em evolução
