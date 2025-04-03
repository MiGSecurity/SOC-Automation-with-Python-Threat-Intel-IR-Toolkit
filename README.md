# 🛡️ ThreatScan - SOC Automation Toolkit

A Python-based automation toolkit that streamlines common SOC analyst tasks, combining threat intelligence enrichment and simple incident response actions. For example, create a script or small web app that takes an indicator (IP address, domain, or file hash) from an alert and automatically queries multiple threat intelligence sources (e.g. VirusTotal, AbuseIPDB, Shodan) to gather reputation data and context​.
The tool can then output a consolidated report with details like malicious score, geolocation of an IP, domain WHOIS info, or related threat intel hits. Additionally, develop an automation to perform a response action: for instance, a Python script to quarantine a host or block an IP by interfacing with a firewall or cloud security group API.

### 🔍 Features

- Multi-source intel (VirusTotal, AbuseIPDB, Shodan, OTX)
- Risk scoring with context-based logic
- Automatic submission to AlienVault OTX
- Color-coded CLI output
- JSON log generation

### 📦 Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/threatscan.git
   cd threattool
   ```
   pip install -r requirements.txt
   cp config.ini.example config.ini

# Then edit config.ini with your keys

Example:
 ```bash
python threatscan.py --indicator 8.8.8.8
 ```
🧠 TODO

   Domain and hash support

   Web GUI with Streamlit

   Modular refactor
