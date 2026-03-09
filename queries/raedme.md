```
# Microsoft Sentinel Detection Queries

This directory contains **Kusto Query Language (KQL) detection queries** used in the Azure Sentinel honeypot SOC lab.

The queries analyze **Linux Syslog authentication logs** collected from a Cowrie SSH honeypot deployed in Microsoft Azure.

Logs are ingested using the **Azure Monitor Agent** into a **Log Analytics Workspace**, where Microsoft Sentinel performs threat detection and investigation.

---

## Data Source

Log Source: Linux Syslog  
Honeypot: Cowrie SSH Honeypot  
Platform: Microsoft Sentinel (SIEM)

The queries analyze SSH authentication events such as:

- Failed login attempts
- Attacker IP addresses
- Targeted usernames
- Brute-force behavior
- Attack timelines

---

## Detection Queries Included

### SSH Brute Force Detection
Detects repeated authentication attempts against the SSH honeypot.

File:
```
ssh_bruteforce_detection.kql

```

MITRE Technique:
T1110 – Brute Force



### Top Attacker IP Detection

Identifies the most active attacker IP addresses targeting the honeypot.

File:
```
top_attacker_ips.kql
```

Purpose:

- Identify attacking infrastructure
- Track scanning sources
- Support threat intelligence investigation

---

### Targeted Username Detection

Identifies usernames attackers attempt to brute force.

File:
```
targeted_usernames.kql
```

Purpose:

- Identify targeted accounts
- Detect credential stuffing attempts
- Understand attacker reconnaissance patterns

---

### Brute Force Behavior Detection

Detects high-frequency authentication attempts from a single source within a short time window.

File:
```
bruteforce_behavior_detection.kql

```

MITRE Technique:
T1110 – Brute Force

---

### Attack Timeline Visualization

Displays attack frequency over time to visualize scanning patterns and attack spikes.

File:
```
attack_timeline.kql
```

---

## SOC Use Case

These queries allow security analysts to:

- Identify active brute-force attacks
- Detect attacker reconnaissance activity
- Monitor authentication abuse
- Investigate attacker infrastructure
- Build detection rules and alerts in Microsoft Sentinel

---

## Notes

These queries were executed successfully against real attack traffic captured by the Azure honeypot environment.

The honeypot began receiving automated attack activity within minutes of exposure to the internet, demonstrating the prevalence of automated SSH scanning and brute-force attacks.
```

