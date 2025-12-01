
# 📸 Guia Completo de Screenshots - Enterprise SOC Lab

Guia detalhado para capturar screenshots profissionais de qualidade para documentação do projeto.

---

## 📋 Índice

1. [Ferramentas de Captura](#ferramentas-de-captura)
2. [Boas Práticas](#boas-práticas)
3. [Screenshots do Wazuh](#screenshots-do-wazuh)
4. [Screenshots do Splunk](#screenshots-do-splunk)
5. [Screenshots do Windows](#screenshots-do-windows)
6. [Screenshots de Rede](#screenshots-de-rede)
7. [Screenshots do Kali](#screenshots-do-kali)
8. [Organização dos Arquivos](#organização-dos-arquivos)

---

## Ferramentas de Captura

### Windows (Host)

**1. Snipping Tool Nativo (Recomendado)**
```
Atalho: Win + Shift + S
```
- Selecionar área
- Copia automaticamente para clipboard
- Colar no Paint ou salvar direto

**2. Snip & Sketch**
```
Atalho: Win + Shift + S → Abrir Snip & Sketch
```
- Anotações
- Destaque
- Régua

**3. Print Screen Tradicional**
```
Print Screen = Tela inteira
Alt + Print Screen = Janela ativa
```

**4. ShareX (Software Gratuito - Opcional)**
- Download: https://getsharex.com/
- Captura automática com marcação
- Numeração automática
- Upload direto

### Linux (dentro das VMs)

**GNOME Screenshot:**
```bash
gnome-screenshot
gnome-screenshot -w  # Janela ativa
gnome-screenshot -a  # Selecionar área
```

**Flameshot (Recomendado):**
```bash
sudo apt install flameshot -y
flameshot gui  # Interface gráfica
```

**Shutter:**
```bash
sudo apt install shutter -y
shutter -f  # Full screen
shutter -a  # Área selecionada
```

---

## Boas Práticas

### ✅ FAZER

1. **Resolução e Qualidade**
   - Usar resolução nativa (1920x1080 ou superior)
   - Salvar em PNG (melhor qualidade)
   - Evitar JPEG (perda de qualidade)

2. **Composição**
   - Capturar tela inteira quando mostrar contexto
   - Capturar área específica para detalhes
   - Incluir barra de título da janela
   - Mostrar data/hora quando relevante

3. **Visibilidade**
   - Usar tema claro ou escuro consistente
   - Garantir contraste adequado
   - Texto legível
   - Zoom adequado (100-125%)

4. **Conteúdo**
   - Dados reais (não lorem ipsum)
   - Mostrar funcionalidade real
   - Evidenciar pontos importantes
   - Incluir informações contextuais

5. **Nomenclatura**
   - Usar nomes descritivos
   - Incluir numeração sequencial
   - Formato: `01-wazuh-dashboard-main.png`
   - Consistência em todos os arquivos

### ❌ EVITAR

1. **Não fazer:**
   - Screenshots desfocados
   - Imagens cortadas de forma estranha
   - Telas vazias sem dados
   - Incluir informações sensíveis reais
   - Prints com erros ou falhas

2. **Não mostrar:**
   - Senhas reais
   - Endereços de email pessoais reais
   - Informações privadas
   - Dados de produção

3. **Não usar:**
   - JPEG para screenshots técnicos
   - Resolução muito baixa
   - Proporções distorcidas

---

## Screenshots do Wazuh

**Acessar:** `https://192.168.1.102`  
**Login:** admin / [sua senha]

### 📸 Screenshot 1: Dashboard Principal

**Arquivo:** `screenshots/wazuh/01-dashboard-main.png`

**O que capturar:**
- Dashboard Home completo
- Menu lateral visível
- Estatísticas principais (cards no topo)
- Gráficos de eventos
- Timeline de alertas

**Como fazer:**
1. Fazer login no Wazuh Dashboard
2. Ir para Home / Overview
3. Rolar para mostrar seção principal
4. **Win + Shift + S**
5. Selecionar toda a janela do navegador
6. Salvar como `01-dashboard-main.png`

**Dica:** Maximize o navegador antes de capturar

---

### 📸 Screenshot 2: Agents Overview

**Arquivo:** `screenshots/wazuh/02-agents-overview.png`

**O que capturar:**
- Menu → Agents → Overview
- Lista de agentes conectados (DC01, ubuntu-lab)
- Status: Active
- Last keep alive
- OS information

**Checklist:**
- [ ] Mostrar pelo menos 2 agentes
- [ ] Status "Active" visível
- [ ] Coluna "OS" preenchida
- [ ] Barra de busca visível

---

### 📸 Screenshot 3: Security Events

**Arquivo:** `screenshots/wazuh/03-security-events.png`

**Antes de capturar:**
1. Gerar atividade de teste:
```powershell
# No Windows DC01
Start-Process notepad
Stop-Process -Name notepad -Force
```

**O que capturar:**
- Menu → Security Events
- Timeline de eventos
- Filtros à esquerda
- Lista de eventos
- Detalhes de pelo menos 1 evento

**Dica:** Aplicar filtro `agent.name: "DC01"` para focar no Windows

---

### 📸 Screenshot 4: Threat Detection / Rule Analysis

**Arquivo:** `screenshots/wazuh/04-threat-detection.png`

**O que capturar:**
- Menu → Threat Detection → MITRE ATT&CK
- Ou: Menu → Rules
- Visualização de técnicas detectadas
- Ou: Lista de regras ativas

**Opção 1 - MITRE ATT&CK:**
- Heatmap de técnicas
- Táticas na parte superior
- Técnicas coloridas por frequência

**Opção 2 - Rules:**
- Lista de regras
- Rule ID, Description, Level
- Filtros ativos

---

### 📸 Screenshot 5: Agent Details

**Arquivo:** `screenshots/wazuh/05-agent-dc01-details.png`

**O que capturar:**
- Agents → Selecionar DC01
- Overview do agente específico
- Informações do sistema
- Últimos eventos
- Módulos ativos

---

## Screenshots do Splunk

**Acessar:** `http://192.168.1.51:8000`  
**Login:** admin / [sua senha]

### 📸 Screenshot 6: Splunk Homepage

**Arquivo:** `screenshots/splunk/01-homepage.png`

**O que capturar:**
- Página inicial do Splunk
- Apps disponíveis
- Search & Reporting
- Dashboards
- Barra de navegação superior

---

### 📸 Screenshot 7: Search Interface

**Arquivo:** `screenshots/splunk/02-search-interface.png`

**Antes de capturar:**
1. Executar search:
```spl
index=sysmon EventCode=1
| head 20
| table _time, Computer, User, Image, CommandLine
```

**O que capturar:**
- Barra de search com query visível
- Time picker
- Resultados em formato tabela
- Estatísticas (Events, Hosts)
- Barra lateral (Fields)

**Checklist:**
- [ ] Query visível e legível
- [ ] Pelo menos 5-10 resultados
- [ ] Colunas bem formatadas
- [ ] Time range visível

---

### 📸 Screenshot 8: Dashboard Example

**Arquivo:** `screenshots/splunk/03-dashboard-example.png`

**Criar dashboard simples:**
1. Na search, clicar "Save As" → Dashboard Panel
2. Dashboard: "SOC Overview"
3. Adicionar:
   - Chart de eventos por hora
   - Top 5 hosts
   - Top 5 Event IDs

**O que capturar:**
- Dashboard completo
- Múltiplos painéis
- Títulos dos painéis
- Gráficos com dados

---

### 📸 Screenshot 9: Sysmon Logs no Splunk

**Arquivo:** `screenshots/splunk/04-sysmon-logs.png`

**Search:**
```spl
index=sysmon
| stats count by EventCode
| sort -count
```

**O que capturar:**
- Query de Sysmon
- Distribuição por Event Code
- Visualização (table ou chart)
- Volume de eventos

---

### 📸 Screenshot 10: Data Inputs

**Arquivo:** `screenshots/splunk/05-data-inputs.png`

**O que capturar:**
- Settings → Data Inputs
- Lista de inputs configurados
- Status: Enabled
- Porta 9997 (se usando forwarder)

---

## Screenshots do Windows

**Máquina:** Windows Server DC01

### 📸 Screenshot 11: Event Viewer - Security

**Arquivo:** `screenshots/windows/01-event-viewer-security.png`

**Como abrir:**
```
Win + R → eventvwr.msc → Enter
```

**O que capturar:**
- Event Viewer completo
- Windows Logs → Security selecionado
- Lista de eventos
- Painel de detalhes de 1 evento expandido

**Dica:** Selecionar evento interessante (Event ID 4624, 4688)

---

### 📸 Screenshot 12: Sysmon Operational

**Arquivo:** `screenshots/windows/02-sysmon-operational.png`

**Navegação:**
```
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

**O que capturar:**
- Caminho completo visível
- Lista de eventos Sysmon
- Detalhes de evento (Event ID 1 ou 3)

---

### 📸 Screenshot 13: Event Details (Sysmon Process Creation)

**Arquivo:** `screenshots/windows/03-sysmon-event-details.png`

**O que capturar:**
- Event ID 1 (Process Creation)
- Detalhes completos:
  - Image (caminho do executável)
  - CommandLine
  - User
  - ParentImage
- Tab "Details" aberta
- XML view (opcional)

---

### 📸 Screenshot 14: Services (Wazuh, Splunk, Sysmon)

**Arquivo:** `screenshots/windows/04-services-running.png`

**Como abrir:**
```powershell
services.msc
```

**O que capturar:**
- Services console
- Filtrar ou rolar para mostrar:
  - Sysmon64 (Running)
  - Splunkd (Running)
  - WazuhSvc (Running)

**Ou via PowerShell:**
```powershell
Get-Service | Where-Object {$_.Name -like "*wazuh*" -or $_.Name -like "*splunk*" -or $_.Name -like "*sysmon*"}
```
Capturar output do PowerShell

---

### 📸 Screenshot 15: PowerShell Commands

**Arquivo:** `screenshots/windows/05-powershell-commands.png`

**Executar alguns comandos:**
```powershell
# Mostrar hostname e IP
hostname
Get-NetIPAddress -AddressFamily IPv4

# Listar processos
Get-Process | Select-Object -First 10

# Ver eventos Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

**O que capturar:**
- PowerShell com comandos executados
- Output visível
- Prompt mostrando "Administrator" (se admin)

---

### 📸 Screenshot 16: Task Manager / Processes

**Arquivo:** `screenshots/windows/06-task-manager.png`

**Como abrir:**
```
Ctrl + Shift + Esc
```

**O que capturar:**
- Tab "Processes"
- Mostrar processos do lab:
  - Sysmon64.exe
  - splunkd.exe
  - ossec-agent.exe (Wazuh)

---

## Screenshots de Rede

**Máquina:** pfSense

### 📸 Screenshot 17: pfSense Dashboard

**Arquivo:** `screenshots/network/01-pfsense-dashboard.png`

**Acessar:** `http://192.168.1.1`  
**Login:** admin / pfsense (ou sua senha)

**O que capturar:**
- Dashboard principal
- System Information
- Interface Statistics
- CPU/Memory usage
- Version visible

---

### 📸 Screenshot 18: Firewall Rules

**Arquivo:** `screenshots/network/02-pfsense-firewall-rules.png`

**Navegação:**
```
Firewall → Rules → LAN
```

**O que capturar:**
- Lista de regras
- Colunas: Action, Interface, Protocol, Source, Destination
- Pelo menos 3-5 regras visíveis

---

### 📸 Screenshot 19: DHCP Leases

**Arquivo:** `screenshots/network/03-pfsense-dhcp-leases.png`

**Navegação:**
```
Status → DHCP Leases
```

**O que capturar:**
- Lista de leases ativos
- Colunas: IP, MAC, Hostname
- Mostrar as 5 VMs do lab

---

### 📸 Screenshot 20: Interfaces Status

**Arquivo:** `screenshots/network/04-pfsense-interfaces.png`

**Navegação:**
```
Status → Interfaces
```

**O que capturar:**
- WAN e LAN interfaces
- Status: up
- IP addresses
- MAC addresses

---

## Screenshots do Kali

**Máquina:** Kali Linux

### 📸 Screenshot 21: Nmap Scan

**Arquivo:** `screenshots/kali/01-nmap-scan.png`

**Executar:**
```bash
nmap -sS 192.168.1.51
```

**O que capturar:**
- Terminal com comando visível
- Output do Nmap
- Portas descobertas
- Timestamp

---

### 📸 Screenshot 22: Attack Simulation

**Arquivo:** `screenshots/kali/02-attack-simulation.png`

**Opções:**

**Opção 1 - Hydra:**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.101
```

**Opção 2 - Metasploit:**
```bash
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.51
run
```

**O que capturar:**
- Terminal com ferramenta rodando
- Comando visível
- Output inicial

---

## Organização dos Arquivos

### Estrutura Final

```
screenshots/
├── wazuh/
│   ├── 01-dashboard-main.png
│   ├── 02-agents-overview.png
│   ├── 03-security-events.png
│   ├── 04-threat-detection.png
│   └── 05-agent-dc01-details.png
│
├── splunk/
│   ├── 01-homepage.png
│   ├── 02-search-interface.png
│   ├── 03-dashboard-example.png
│   ├── 04-sysmon-logs.png
│   └── 05-data-inputs.png
│
├── windows/
│   ├── 01-event-viewer-security.png
│   ├── 02-sysmon-operational.png
│   ├── 03-sysmon-event-details.png
│   ├── 04-services-running.png
│   ├── 05-powershell-commands.png
│   └── 06-task-manager.png
│
├── network/
│   ├── 01-pfsense-dashboard.png
│   ├── 02-pfsense-firewall-rules.png
│   ├── 03-pfsense-dhcp-leases.png
│   └── 04-pfsense-interfaces.png
│
└── kali/
    ├── 01-nmap-scan.png
    └── 02-attack-simulation.png
```

### Metadata dos Screenshots

Criar arquivo `screenshots/README.md`:

```markdown
# Screenshots - Enterprise SOC Lab

## Índice de Screenshots

### Wazuh (5 screenshots)
1. Dashboard principal - Visão geral do SIEM
2. Agents overview - Agentes conectados
3. Security events - Timeline de eventos
4. Threat detection - MITRE ATT&CK ou Rules
5. Agent details - Detalhes do DC01

### Splunk (5 screenshots)
1. Homepage - Interface principal
2. Search interface - Query execution
3. Dashboard - Painéis customizados
4. Sysmon logs - Análise de telemetria
5. Data inputs - Fontes de dados

### Windows (6 screenshots)
1. Event Viewer Security - Logs de segurança
2. Sysmon Operational - Telemetria avançada
3. Event details - Detalhes de evento Sysmon
4. Services - Serviços do lab rodando
5. PowerShell - Comandos executados
6. Task Manager - Processos ativos

### Network (4 screenshots)
1. pfSense Dashboard - Overview do firewall
2. Firewall rules - Regras configuradas
3. DHCP leases - IPs distribuídos
4. Interfaces - Status de rede

### Kali (2 screenshots)
1. Nmap scan - Escaneamento de rede
2. Attack simulation - Simulação de ataque

## Informações Técnicas

- **Formato:** PNG
- **Resolução:** 1920x1080 (ou nativa)
- **Total:** 22 screenshots
- **Tamanho estimado:** 10-20 MB total
```

---

## 📝 Checklist de Captura

### Antes de Começar
- [ ] Todos os serviços rodando
- [ ] Gerar atividade de teste
- [ ] Verificar resolução da tela
- [ ] Limpar área de trabalho (desktops das VMs)
- [ ] Fechar notificações desnecessárias

### Durante a Captura
- [ ] Usar nomenclatura consistente
- [ ] Verificar que a imagem está nítida
- [ ] Incluir contexto suficiente
- [ ] Mostrar dados reais (não telas vazias)

### Após Captura
- [ ] Revisar todas as imagens
- [ ] Verificar qualidade
- [ ] Organizar em pastas corretas
- [ ] Criar README.md em screenshots/
- [ ] Fazer commit no Git

---

## 🎨 Pós-Processamento (Opcional)

### Ferramentas

**Windows:**
- Paint (nativo) - Para anotações básicas
- Paint.NET - Gratuito, mais recursos
- GIMP - Profissional, gratuito

**Linux:**
- GIMP
- Krita
- Pinta

### Edições Recomendadas

1. **Adicionar setas ou destaque:**
   - Destacar informações importantes
   - Usar vermelho para alertas
   - Verde para status OK

2. **Recortar bordas:**
   - Remover espaço desnecessário
   - Manter proporção

3. **Adicionar numeração:**
   - Se mostrando sequência de passos

4. **Blur de informações sensíveis:**
   - Se necessário ocultar algo

---

## 🚀 Ação Rápida

**Tempo estimado:** 1-2 horas para capturar tudo

**Ordem sugerida:**
1. Wazuh (15 min)
2. Splunk (15 min)
3. Windows (20 min)
4. pfSense (15 min)
5. Kali (10 min)
6. Organizar e renomear (15 min)

---

## ✅ Validação Final

Antes de dar como concluído:
- [ ] Todas as 22 screenshots capturadas
- [ ] Nomes consistentes com numeração
- [ ] Organizadas em subpastas
- [ ] README.md criado
- [ ] Qualidade verificada (nítidas, legíveis)
- [ ] Tamanho total razoável (<30 MB)
- [ ] Commitadas no Git

**Pronto para uso no GitHub!** 🎉
