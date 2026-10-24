<#
.SYNOPSIS
    Export Windows logon events (4624 success, 4625 failure) to the CSV format Login Sentinel reads.

.DESCRIPTION
    Reading the Security log needs an elevated (Run as administrator) PowerShell window.
    Field values are read by name from each event's XML, which is more reliable than
    relying on property positions that differ between event IDs.

.EXAMPLE
    .\export_windows_events.ps1 -Hours 24 -Path .\windows_security.csv
    python -m login_sentinel .\windows_security.csv
#>
param(
    [int]$Hours = 24,
    [string]$Path = ".\windows_security.csv"
)

$since = (Get-Date).AddHours(-$Hours)

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625; StartTime = $since } -ErrorAction Stop |
    ForEach-Object {
        $data = @{}
        foreach ($field in ([xml]$_.ToXml()).Event.EventData.Data) { $data[$field.Name] = $field.'#text' }
        [PSCustomObject]@{
            TimeCreated     = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
            EventID         = $_.Id
            TargetUserName  = $data['TargetUserName']
            IpAddress       = $data['IpAddress']
            WorkstationName = $data['WorkstationName']
        }
    } |
    Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

Write-Host "Exported logon events from the last $Hours hours to $Path"
