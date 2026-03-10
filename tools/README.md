# Tools Used in This Lab

This directory references security tools used during the SOC detection lab.

---

## DeepBlueCLI

DeepBlueCLI is a Windows security event log analysis tool used to detect suspicious activity in Windows Event Logs.

It analyzes logs for indicators such as:

- Failed logon attempts
- Privileged logons
- PowerShell execution
- Suspicious command execution
- Lateral movement indicators

### Repository

https://github.com/sans-blue-team/DeepBlueCLI

### Usage Example

```powershell
.\DeepBlue.ps1
```
Example Output
DeepBlueCLI was used to analyze Windows Security logs collected from the Active Directory Domain Controller in this lab.
Example detected events:

```
4625 – Failed Logon Attempts
4624 – Successful Logons
4672 – Special Privileges Assigned
4648 – Explicit Credential Logon
```
These events help identify suspicious authentication behavior in enterprise environments.

Purpose in This Project:
DeepBlueCLI was used to:-
Analyze Windows authentication logs
Detect suspicious login behavior
Investigate privileged access events
Support SOC-style threat hunting workflows

