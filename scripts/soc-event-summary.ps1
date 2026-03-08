# SOC Security Event Summary Script
# Collects important Windows Security Event IDs for SOC monitoring

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

Write-Host "=============================="
Write-Host "   SOC SECURITY EVENT SUMMARY"
Write-Host "=============================="

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
        Count = $_.Count
        Description = $ImportantEvents[[int]$_.Name]
    }
} | Format-Table -AutoSize
