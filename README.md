<div align="center">

# 🔒 AI-Powered PCAP Analyzer for SOC Operations
  
  <img
    width="480"
    height="480"
    alt="Image"
    src="https://github.com/user-attachments/assets/9f640abc-94be-478f-aee2-7b3cdad0e575"
  />
</div>


A powerful Python tool that leverages AI to analyze network traffic captures (PCAP files) and identify security threats. Built for Security Operations Center (SOC) analysts, penetration testers, and network security professionals.

## ✨ Features

- **🤖 Universal AI Model Support**: Works with ANY Ollama model (Llama, Mistral, Qwen, CodeLlama, Phi3, etc.)
- **📊 Comprehensive Traffic Analysis**: Deep packet inspection with protocol breakdown
- **🛡️ Security Threat Detection**: Identifies DDoS attacks, port scans, suspicious domains, and malicious ports
- **💾 Memory-Optimized**: Streams large PCAP files efficiently without loading everything into memory
- **📈 Statistical Analysis**: Traffic patterns, top talkers, DNS queries, and more
- **📄 JSON Reports**: Generates detailed analysis reports with AI insights
- **🎯 IOC Extraction**: Automatically identifies Indicators of Compromise (IPs, ports, domains)

## 🚀 Quick Start

### Prerequisites

1. **Python 3.7+** with required packages:
```bash
pip install scapy requests
```

2. **Ollama** - Install from [ollama.ai](https://ollama.ai)

3. **Pull an AI model**:
```bash
# Lightweight model (recommended for quick analysis)
ollama pull qwen2.5:0.5b

# Or use more powerful models
ollama pull llama3.2
ollama pull mistral
```

### Installation

```bash
# Clone the repository
https://github.com/RiadMoudjahed/AI-Powered-PCAP-Analyzer.git
cd ai-pcap-analyzer

# Install dependencies
pip install -r requirements.txt

# Start Ollama service
ollama serve
```

### Basic Usage

```bash
# Analyze a PCAP file with default model
python AI-Based_wireshark_analyzer.py capture.pcap

# Use a specific model
python AI-Based_wireshark_analyzer.py capture.pcap --model qwen2.5:0.5b

# Limit packet analysis (for large files)
python AI-Based_wireshark_analyzer.py capture.pcap --max-packets 5000

# Save to custom output file
python AI-Based_wireshark_analyzer.py capture.pcap -o my_report.json
```

## 📋 Example Analysis

### Sample Traffic Summary
```
============================================================
📊 ANALYSIS SUMMARY
============================================================
Total Packets: 11,182

📈 Protocol Distribution:
  TCP: 11,181
  UDP: 1

🔒 Security Assessment:
  Risk Score: 25/100
  Threat Indicators: 0
  Potential Attacks: 1

🌐 Top Source IPs:
  10.0.15.42: 6,287 packets
  192.168.1.110: 4,893 packets
  192.168.1.1: 1 packets
```

### AI Security Analysis Output

```
🤖 AI SECURITY ANALYSIS
============================================================

EXECUTIVE SUMMARY
The network traffic analysis reveals 11,182 packets over a 7-second period, 
predominantly TCP traffic. A potential DDoS attack pattern has been identified 
targeting internal host 192.168.1.110, comprising 56% of total traffic.

CRITICAL FINDINGS
- Potential DDoS Attack: 6,288 packets directed at 192.168.1.110 (56% of traffic)
- TCP Flood Pattern: Excessive TCP connections detected
- High Traffic Volume: Average packet size of 844 bytes indicates data-heavy traffic

ATTACK INDICATORS
- Abnormal traffic concentration to single destination IP
- TCP sequences showing multiple data streams
- Port 443 (HTTPS) and ephemeral port 49872 heavily utilized
- Single source IP (10.0.15.42) responsible for majority of traffic

RISK LEVEL: Medium

RECOMMENDATIONS
1. Implement traffic filtering to rate-limit incoming connections
2. Deploy Intrusion Detection Systems (IDS) for real-time monitoring
3. Configure firewall rules to block suspicious traffic patterns
4. Conduct regular security audits of network architecture
5. Update all network software to latest security patches

IOCs (Indicators of Compromise)
- Source IPs: 10.0.15.42, 192.168.1.110
- Destination IP: 192.168.1.110
- Ports: 443 (HTTPS), 49872 (ephemeral)
- Attack Pattern: DDoS/TCP Flood
```

## 🔍 What It Analyzes

### Network Statistics
- Protocol distribution (TCP, UDP, ICMP, DNS, ARP)
- Top source and destination IPs
- Most active ports
- Traffic volume and patterns
- Average packet sizes

### Security Analysis
- **Port Scans**: Detects hosts probing multiple ports
- **DDoS Attacks**: Identifies traffic flooding patterns
- **Suspicious Ports**: Flags connections to known malicious ports (4444, 5555, 31337, etc.)
- **Exploit Attempts**: Monitors access to vulnerable service ports (445, 3389, 3306, etc.)
- **DNS Analysis**: Checks for suspicious domain queries
- **Risk Scoring**: Calculates overall security risk (0-100)

### AI-Powered Insights
- Executive summary of findings
- Threat severity classification
- Attack pattern recognition
- Actionable security recommendations
- Evidence-based IOC extraction

## 🎯 Use Cases

- **Security Operations Centers (SOC)**: Rapid incident response and threat analysis
- **Penetration Testing**: Post-exploitation traffic analysis
- **Network Forensics**: Investigation of security incidents
- **Threat Hunting**: Proactive security monitoring
- **Training & Education**: Learning network security concepts

## 📊 Output Format

The tool generates a comprehensive JSON report containing:

```json
{
  "metadata": {
    "filename": "capture.pcap",
    "total_packets": 11182,
    "analysis_timestamp": "2025-12-19T17:24:40.530377"
  },
  "model_used": "qwen2.5:0.5b",
  "statistics": {
    "protocols": {...},
    "top_talkers": {...},
    "dns": {...},
    "traffic_patterns": {...}
  },
  "security_analysis": {
    "threat_indicators": [...],
    "suspicious_ports": [...],
    "potential_attacks": [...],
    "risk_score": 25
  },
  "ai_analysis": "Detailed AI-generated security report..."
}
```

## 🛠️ Advanced Features

### Memory Optimization
The tool uses streaming to handle large PCAP files without memory issues:
- Processes packets on-the-fly
- Progress indicators for long-running analyses
- Configurable packet limits

### Flexible AI Models
Works with any Ollama model:
- Small models (0.5B parameters): Fast analysis
- Large models (7B+ parameters): Deeper insights
- Specialized models: Domain-specific analysis

### Customizable Analysis
- Adjust packet sampling for large captures
- Configure security thresholds
- Custom output file locations

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.


## ⚠️ Disclaimer

This tool is intended for legitimate security analysis purposes only. Always ensure you have proper authorization before analyzing network traffic. The authors are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet processing
- Powered by [Ollama](https://ollama.ai) for AI analysis
- Inspired by the need for automated threat detection in SOC operations

---

**Star ⭐ this repository if you find it useful!**
