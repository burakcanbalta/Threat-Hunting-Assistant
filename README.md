# 🕵️ Threat Hunting Assistant

An advanced **Threat Hunting and Security Analytics** platform built for SOC analysts and cybersecurity researchers.  
Automate hunting workflows, correlate IOCs, and generate actionable intelligence using ML-powered detection.

---

## 🚀 Quick Start

### **Prerequisites**
```bash
# Python 3.8+
python --version

# Install required packages
pip install pandas numpy scikit-learn elasticsearch
```

### **Installation & Setup**
```bash
# 1. Clone the repository
git clone https://github.com/burakcanbalta/ThreatHuntingAssistant.git
cd ThreatHuntingAssistant

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure data sources
cp config.json.example config.json
# Edit config.json with your SIEM and log sources

# 4. Run threat hunting scenario
python threat_hunter.py --scenario lateral_movement

# 5. Generate hunting report
python threat_hunter.py --report --format json
```

---

## 🧠 Basic Usage

```bash
# Run specific hunting scenarios
python threat_hunter.py --scenario lateral_movement
python threat_hunter.py --scenario persistence
python threat_hunter.py --scenario data_exfiltration

# Hunt with custom IOCs
python threat_hunter.py --ioc-file iocs.json

# Generate hunting report
python threat_hunter.py --report --format html

# Continuous monitoring
python threat_hunter.py --monitor --interval 3600
```

---

## 📋 requirements.txt
```txt
pandas==2.0.3
numpy==1.24.3
scikit-learn==1.3.0
elasticsearch==8.9.0
aiohttp==3.8.5
PyYAML==6.0.1
Jinja2==3.1.2
```

---

## 🎯 Use Cases

### **SOC Proactive Hunting**
```bash
python threat_hunter.py --scenario lateral_movement
# ✅ Hunting completed: 15 findings
# 🚨 HIGH severity: 3 findings
```

### **Incident Response**
```bash
python threat_hunter.py --scenario persistence
python threat_hunter.py --scenario command_control
```

### **Compliance & Auditing**
```bash
python threat_hunter.py --report --days 30 --format html
```

### **Threat Intelligence**
```bash
python threat_hunter.py --monitor --interval 1800
```

---

## 📊 Sample Output

### **Hunting Session Results**
```json
{
  "session_id": "lateral_movement_20231215_143022",
  "scenario": "lateral_movement",
  "timestamp": "2023-12-15T14:30:22",
  "summary": {
    "total_findings": 8,
    "high_severity": 2,
    "medium_severity": 4,
    "low_severity": 2,
    "average_confidence": 0.75
  },
  "findings": [
    {
      "finding_type": "IOC_MATCH",
      "severity": "HIGH",
      "description": "IOC Match: evil-c2.com",
      "evidence": "Found in domain feed matching lateral_movement scenario",
      "confidence": 0.9
    }
  ]
}
```

### **Comprehensive Report**
```text
Threat Hunting Comprehensive Report
============================================================
Period: Last 7 days
Generated: 2023-12-15T14:35:10

Scenario Statistics:
------------------------------
lateral_movement: 5 sessions, 6.2 avg findings
persistence: 3 sessions, 4.5 avg findings
data_exfiltration: 2 sessions, 3.0 avg findings

Finding Statistics:
------------------------------
IOC_MATCH (HIGH): 15 findings
BEHAVIORAL (MEDIUM): 22 findings
ANOMALY (HIGH): 8 findings

IOC Statistics:
------------------------------
domain: 12 matches
ip: 8 matches
url: 5 matches
```

---

## 🔧 Advanced Usage

### **Custom Hunting Playbooks**
```yaml
name: custom_hunt
description: "Custom threat hunting scenario"
techniques: ["T1055", "T1059"]
queries:
  elasticsearch:
    - "process.name:powershell AND command_line:*-EncodedCommand*"
  splunk:
    - "index=windows sourcetype=WinEventLog:Security EventCode=4688"
iocs: ["Suspicious PowerShell commands", "Process injection patterns"]
confidence_threshold: 0.8
```

### **API Integration**
```python
hunter = ThreatHuntingAssistant()
results = hunter.run_hunting_scenario("data_exfiltration")

for finding in results:
    if finding['severity'] == 'HIGH':
        send_alert_to_siem(finding)
```

### **Automated Response**
```python
if finding['finding_type'] == 'IOC_MATCH' and finding['ioc_type'] == 'ip':
    block_ip_address(finding['ioc_value'])
```

---

## 🐛 Troubleshooting

### **Data Source Connectivity**
```json
{
  "elasticsearch": {
    "hosts": ["http://elasticsearch:9200"],
    "timeout": 60,
    "retry_on_timeout": true
  }
}
```

### **Performance Optimization**
```python
config = {
    "hunting": {
        "max_results": 5000,
        "parallel_scans": 3
    }
}
```

### **ML Model Tuning**
```json
{
  "ml": {
    "contamination": 0.05,
    "n_estimators": 100,
    "max_samples": 256
  }
}
```

---

## 🤝 Contributing

1. Fork the repository  
2. Create feature branch  
   ```bash
   git checkout -b feature/advanced-hunting
   ```
3. Commit changes  
   ```bash
   git commit -am 'Add new hunting technique'
   ```
4. Push branch  
   ```bash
   git push origin feature/advanced-hunting
   ```
5. Create Pull Request

**Contribution Areas:**
- New hunting scenarios & techniques  
- Additional data source connectors  
- Enhanced ML models  
- Advanced correlation algorithms  
- Visualization & dashboarding
