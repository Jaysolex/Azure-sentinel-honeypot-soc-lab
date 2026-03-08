<#
SOC Detection Lab - Security Event Summary

Author: Solomon James
Purpose: Collect and summarize important Windows Security Event IDs from the
Security event log to help detect suspicious authentication activity,
privileged access, and potential attack patterns in a SOC environment.

Summarize critical Windows Security Event IDs for SOC monitoring.

Events monitored:
4625 - Failed Logon Attempt
4624 - Successful Logon
4648 - Explicit Credential Logon
4672 - Special Privileges Assigned
4673 - Sensitive Privilege Use
4720 - User Account Created
4728 - User Added to Privileged Group
4732 - User Added to Local Admin Group
1102 - Audit Log Cleared
#>

Write-Host ""
Write-Host "===================================="
Write-Host "      SOC SECURITY EVENT SUMMARY"
Write-Host "===================================="
Write-Host ""

# Important SOC Event IDs
$ImportantEvents = @{
    4625 = "Failed Logon Attempt"
    4624 = "Successful Logon"
    4648 = "Explicit Credential Logon"
    4672 = "Special Privileges Assigned"
    4673 = "Sensitive Privilege Use"
    4720 = "User Account Created"
    4728 = "User Added to Privileged Group"
    4732 = "User Added to Local Admin Group"
    1102 = "Audit Log Cleared"
}

# Pull security logs
$events = Get-WinEvent -LogName Security -MaxEvents 5000 |
Where-Object { $ImportantEvents.ContainsKey($_.Id) }

# Summarize results
$events |
Group-Object Id |
Sort-Object Count -Descending |
ForEach-Object {
    [PSCustomObject]@{
        EventID = $_.Name
        Description = $ImportantEvents[[int]$_.Name]
        Count = $_.Count
    }
} | Format-Table -AutoSize

