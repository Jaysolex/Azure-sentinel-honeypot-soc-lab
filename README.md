# Azure-Sentinel-Honeypot-SOC-Lab

End-to-end **cloud SOC detection lab** using a Cowrie SSH honeypot deployed in Microsoft Azure and integrated with **Microsoft Sentinel SIEM** to detect brute-force authentication attempts, attacker reconnaissance activity, credential harvesting, and suspicious login patterns using **KQL threat hunting queries** and **Windows security log analysis**.

---

# Objective

This project demonstrates a **real-world SOC detection workflow**:

- Deploy a public-facing honeypot in Azure  
- Capture real-world SSH attack traffic  
- Ingest Linux Syslog logs into Microsoft Sentinel  
- Perform threat hunting using KQL queries  
- Detect SSH brute-force authentication attempts  
- Identify attacker IP addresses and targeted usernames  
- Analyze authentication patterns and attack timelines  
- Monitor Windows Active Directory security events  
- Use DeepBlueCLI to detect suspicious Windows activity  
- Investigate attacker infrastructure using threat intelligence  
- Map detections to MITRE ATT&CK techniques  

---

# Cloud SOC Architecture

This lab simulates a **cloud SOC monitoring environment** combining honeypot telemetry with SIEM detection.

![SOC Architecture](architecture/soc-lab-architecture.PNG)

---

# Data Flow Explanation

Internet attackers scan public cloud infrastructure.

The Azure VM receives inbound SSH traffic on **port 22**.

iptables redirects traffic to the **Cowrie SSH honeypot running on port 2222**.

Cowrie logs attacker activity including:

- SSH connections  
- Authentication attempts  
- Client fingerprints  
- Executed commands  

Linux Syslog forwards logs to:

- Azure Monitor Agent

Logs are ingested into:

- Log Analytics Workspace

Microsoft Sentinel performs:

- Threat hunting  
- Detection queries  
- Attack investigation  

---
## Sentinel Invalid User Query

This detection query was created in Microsoft Sentinel to identify repeated SSH authentication failures in Linux Syslog logs.

Attackers commonly attempt to brute-force SSH access by trying invalid usernames. By analyzing Syslog authentication logs, we can detect these attempts and identify the attacking IP addresses.

### KQL Query
[`sentinel-invalid-user-query.kql`](queries/sentinel-invalid-user-query.kql)

```kql
Syslog
| where TimeGenerated >= ago(7d)
| where Facility == "auth"
| where SyslogMessage contains "Invalid user"
| extend AttackerIP = extract(@"(\d+\.\d+\.\d+\.\d+)",0,SyslogMessage)
| summarize Attempts=count() by AttackerIP
| extend geo = geo_info_from_ip_address(AttackerIP)
| extend Country = tostring(geo.country)
| project Country, AttackerIP, Attempts
| sort by Attempts desc
```
screenshot: sentinel-invalid-user-query
![sentinel-invalid-user-query](screenshots/sentinel-invalid-user-query.png)


# Detection Walkthrough

## 1️⃣ SSH Brute Force Detection

Query:  
[`queries/ssh_bruteforce_detection.kql`](queries/ssh_bruteforce_detection.kql)

Detects repeated authentication attempts against the honeypot.

```kql
Syslog
| where ProcessName == "sshd"
| where SyslogMessage contains "Invalid user"
| parse SyslogMessage with * "Invalid user " user " from " ip " port " *
| summarize Attempts=count() by ip, user
| order by Attempts desc
```
MITRE Technique: T1110.001 – Brute Force


2️⃣ Top Attacker IP Detection

Query: 
[`queries/top_attacker_ips.kql`](queries/top_attacker_ips.kql)

Identifies the most active attacking IP addresses.

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Invalid user"
| extend AttackerIP = extract(@"\d+\.\d+\.\d+\.\d+", 0, SyslogMessage)
| summarize Attempts=count() by AttackerIP
| sort by Attempts desc
```
📸 Example Detection Output
![top attackers-ip](screenshots/top-attacker-ip-chat.png)

Sentinel SSH Attack Detection


3️⃣ Targeted Username Enumeration

query: 
[`targeted_usernames.kql`](queries/targeted_usernames.kql)

Identifies usernames attackers attempt to brute force.

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Invalid user"
| extend Username = extract(@"Invalid user ([^ ]+)", 1, SyslogMessage)
| summarize Attempts=count() by Username
| sort by Attempts desc
```
![targeted attacker's attept](screenshots/attemppt-to-bruteforce.png)
Attackers commonly probe for:

Admin accounts
Service accounts
Development accounts


4️⃣ Brute Force Behavior Detection

query: [`high-frequency-auth-attempt.kql`](queries/high-frequency-auth-attempt.kql)

Detects high-frequency authentication attempts from a single source.

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Invalid user"
| extend AttackerIP = extract(@"\d+\.\d+\.\d+\.\d+", 0, SyslogMessage)
| summarize Attempts=count() by AttackerIP, bin(TimeGenerated, 5m)
| where Attempts > 5
```
![high-frequency-authentication-attempt](screenshots/high-frequency-authentication-attempt.png)

MITRE Technique: T1110.001 – Brute Force



5️⃣ Attack Timeline Visualization

query: 
[`attack-timeline-visualization`](queries/attack_timeline.kql)

Displays attack frequency over time.
```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Invalid user"
| summarize Attempts=count() by bin(TimeGenerated, 5m)
| render timechart
```
📸 Attack Timeline Visualization
![attack-timeline-visualizatio](screenshots/sentinel_attack_timeline_chart.png)
SSH-Attack-Timeline
This allows SOC analysts to visualize attack spikes and automated scanning behavior


##Active Directory Monitoring#+
A Windows Server 2025 Domain Controller was deployed to simulate enterprise authentication activity.
Security events were collected and analyzed using DeepBlueCLI and PowerShell event analysis.

Example Results:

```
EventID Count Description
4625    2077  Failed Logon Attempt
4624    1414  Successful Logon
4672    1375  Special Privileges Assigned
4648      48  Explicit Credential Logon
```
📸 DeepBlueCLI Threat Detection

![DeepBlueCLi](screenshots/deepbluecli-threat-detections.png)

Honeypot Deployment
Clone Cowrie Repository

```
git clone https://github.com/cowrie/cowrie.git
cd cowrie
```
Create Python Virtual Environment

```bash
python3 -m venv cowrie-env
source cowrie-env/bin/activate
```

Install Dependencies
```
pip install -r requirements.txt
```

Configure Cowrie
```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Start Honeypot
```
python -m twisted cowrie
```

Cowrie listens on:

```
Port 2222
```

Redirect SSH Traffic to Honeypot
```
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

This ensures attackers interacting with port 22 connect to the honeypot instead of the real SSH service.
Threat Intelligence Investigation


Example attacker IP investigated:
```
13.81.183.29
```
ASN:
```
AS8075 – Microsoft Corporation
```
Security intelligence platforms reported 933 attack events associated with this IP.
Security vendors flagging this IP include:

GreyNoise
CriminalIP
CyRadar
MalwareURL
Guardpot

Although the IP belongs to Microsoft Azure, cloud infrastructure is frequently abused by attackers due to:

Disposable virtual machines
Rapidly rotating IP addresses
Global infrastructure access

Indicators of Compromise (IOCs)
Captured attacker IP addresses:
```
64.225.55.168
51.38.98.14
177.36.214.46
46.37.66.191
72.253.251.7
170.64.226.171
89.116.31.97
152.42.203.0
103.200.25.79
13.81.183.29
```
Screenshots

Honeypot Attack Logs
![cowrie-honeypot-attacks](screenshots/cowrie-honeypot-attacks.png)

Sentinel Agent Heartbeat
![sentinel-agent-heartbeat](screenshots/sentinel-agent-heartbeat.png)

SSH Attack Detection
![ssh-attack-detectiomn](screenshots/ssh-attack-detection.png)

DeepBlueCLI Threat Analysis
![DeepBlueCli](screenshots/deepbluecli-event-analysis-1.png)

MITRE ATT&CK Mapping
| Behavior          | Technique |
| ----------------- | --------- |
| SSH Brute Force   | T1110     |
| Credential Access | T1110     |
| Valid Account Use | T1078     |
| Remote Services   | T1021     |
| Command Execution | T1059     |


Skills Demonstrated
```
Cloud Security Engineering
Honeypot Deployment
Linux Server Administration
Threat Intelligence Collection
SOC Threat Hunting
SIEM Integration
KQL Detection Engineering
Windows Security Log Analysis
```

##Tools Used##

```
Microsoft Azure
Microsoft Sentinel
Cowrie SSH Honeypot
Azure Monitor Agent
Log Analytics Workspace
DeepBlueCLI
PowerShell
KQL (Kusto Query Language)
```

##Project Outcome##

This lab demonstrates the ability to:
Deploy a cloud honeypot environment
Capture real attacker activity from the internet
Ingest security telemetry into Microsoft Sentinel
Detect brute-force authentication attempts
Perform threat hunting using KQL queries
Analyze attacker infrastructure using threat intelligence
Build SOC-style detection workflows for real-world attacks





*Figure: Real-world SSH attack attempts captured by the Cowrie honeypot deployed in Microsoft Azure.*  
*Project Author: Solomon James*
