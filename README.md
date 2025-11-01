# Enterprise-SOC-Lab
Laboratório de segurança corporativa simulada: firewall pfSense, coleta centralizada de logs, SIEM (Wazuh/Splunk), análise de eventos Windows e Linux, regras de detecção e resposta a incidentes

# 🛡️ Enterprise SOC Lab

## 📋 Sobre o Projeto
Este laboratório simula um ambiente corporativo de Segurança Operacional (SOC).
O objetivo é demonstrar, passo a passo, como coletar logs, detectar ameaças, investigar alertas e responder a incidentes em um cenário realista.

## 🎯 Objetivos
- Configurar ambiente de coleta de logs
- Implementar SIEM (Splunk/ELK/Wazuh)
- Criar dashboards de monitoramento
- Simular ataques e detectar ameaças
- Documentar análises de incidentes

## 🔧 Tecnologias Utilizadas
- **SIEM:** Splunk / ELK Stack / Wazuh
- **Virtualização:** VirtualBox / VMware
- **Sistemas:** Windows Server, Linux (Ubuntu/Kali)
- **Ferramentas:** Sysmon, Metasploit, Nmap

## 📁 Estrutura do Repositório
```
Enterprise-SOC-Lab/
├── docs/           # Documentação
├── configs/        # Arquivos de configuração
├── scripts/        # Scripts de automação
├── dashboards/     # Dashboards do SIEM
└── reports/        # Relatórios de análise


## 🚀 Como Usar
(A ser preenchido conforme você desenvolve o lab)

## 📊 Status do Projeto
🔨 Em desenvolvimento

## 👤 Autor
Seu Nome - [LinkedIn](seu-linkedin) - [Email](seu-email)

## 📝 Licença
Este projeto está sob a licença MIT.
Este laboratório simula um ambiente corporativo de Segurança Operacional (SOC).
O objetivo é demonstrar, passo a passo, como coletar logs, detectar ameaças, investigar alertas e responder a incidentes em um cenário realista.

Componentes do Ambiente
Firewall pfSense (controle de tráfego e segmentação de rede)
Máquina atacante (Kali Linux)
Servidor Linux (Ubuntu Server) gerando logs e serviços expostos
Servidor Windows (Windows Server / Windows 10) gerando Event Logs
SIEM (Wazuh e/ou Splunk) recebendo, correlacionando e exibindo alertas

Objetivos Técnicos
Coleta e centralização de logs (Windows Event Logs, Syslog, Firewall)
Criação de regras de detecção de ataques (ex: brute force, execução suspeita de PowerShell)
Visualização e análise de alertas no SIEM
Abertura de incidente e resposta inicial
O que este projeto prova

Capacidade prática de configurar um ambiente SOC do zero

Entendimento de rede, controle de acesso e segmentação

Habilidade de analisar eventos de segurança e tomar decisão

Preparação para atuar como Analista SOC (Tier 1 / Tier 2)

Próximas Entregas

Diagrama de rede completo

Passo a passo de instalação do ambiente

Capturas de tela (printscreen) dos alertas gerados

Checklist de resposta a incidente

Playbook inicial de contenção

Autora

Natália Grossi
Blue Team | SOC | Resposta a Incidentes
