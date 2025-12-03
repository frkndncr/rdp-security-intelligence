<#
.SYNOPSIS
    RDP Security Intelligence & Ultra Monitoring System
    Kapsamli RDP Guvenlik Izleme ve Loglama Sistemi
    
.DESCRIPTION
    Bu script asagidaki ozellikleri saglar:
    - Tum RDP baglantilarini loglar (basarili/basarisiz)
    - IP adresinden GeoIP bilgisi ceker (ulke, sehir, ISP)
    - Oturum suresini takip eder
    - Kullanici aktivitelerini kaydeder (acilan programlar, dosyalar)
    - Brute-force saldiri tespiti
    - Real-time alerting (Telegram)
    - Gunluk/haftalik raporlama
    
.AUTHOR
    Furkan Dincer
    
.VERSION
    2.0.0
    
.NOTES
    Windows Server 2016/2019/2022 uyumlu
    PowerShell 5.1+ gerektirir
    Yonetici haklari ile calistirilmalidir
#>

#Requires -RunAsAdministrator

# ==================== CONFIGURATION ====================
$Config = @{
    # Log Dizinleri
    LogBasePath         = "C:\RDP-Security-Logs"
    ConnectionLogPath   = "C:\RDP-Security-Logs\Connections"
    SessionLogPath      = "C:\RDP-Security-Logs\Sessions"
    ActivityLogPath     = "C:\RDP-Security-Logs\Activity"
    AlertLogPath        = "C:\RDP-Security-Logs\Alerts"
    ReportPath          = "C:\RDP-Security-Logs\Reports"
    
    # GeoIP API
    GeoIPProvider       = "ip-api.com"
    
    # Telegram Alert Ayarlari
    EnableTelegramAlert = $true
    TelegramBotToken    = "YOUR_BOT_TOKEN_HERE"
    TelegramChatID      = "YOUR_CHAT_ID_HERE"
    
    # Guvenlik Esikleri
    FailedLoginThreshold    = 5
    FailedLoginTimeWindow   = 300
    SuspiciousCountries     = @("CN", "RU", "KP", "IR")
    
    # Monitoring Ayarlari
    ProcessMonitorInterval  = 30
    SessionCheckInterval    = 60
    
    # Log Retention
    LogRetentionDays        = 90
}

# ==================== INITIALIZATION ====================

function Initialize-LogDirectories {
    $directories = @(
        $Config.LogBasePath,
        $Config.ConnectionLogPath,
        $Config.SessionLogPath,
        $Config.ActivityLogPath,
        $Config.AlertLogPath,
        $Config.ReportPath
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "[+] Dizin olusturuldu: $dir" -ForegroundColor Green
        }
    }
}

function Write-SecurityLog {
    param(
        [string]$LogType,
        [string]$Message,
        [hashtable]$Data,
        [string]$Severity = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $dateStr = Get-Date -Format "yyyy-MM-dd"
    
    $logEntry = [PSCustomObject]@{
        Timestamp   = $timestamp
        Severity    = $Severity
        LogType     = $LogType
        Message     = $Message
        Data        = $Data
        MachineName = $env:COMPUTERNAME
    }
    
    $logFile = switch ($LogType) {
        "Connection"  { Join-Path $Config.ConnectionLogPath "connections_$dateStr.json" }
        "Session"     { Join-Path $Config.SessionLogPath "sessions_$dateStr.json" }
        "Activity"    { Join-Path $Config.ActivityLogPath "activity_$dateStr.json" }
        "Alert"       { Join-Path $Config.AlertLogPath "alerts_$dateStr.json" }
        default       { Join-Path $Config.LogBasePath "general_$dateStr.json" }
    }
    
    $logEntry | ConvertTo-Json -Depth 10 -Compress | Add-Content -Path $logFile -Encoding UTF8
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING"  { "Yellow" }
        "INFO"     { "Cyan" }
        default    { "White" }
    }
    Write-Host "[$timestamp] [$Severity] $Message" -ForegroundColor $color
}

# ==================== GEOIP INTELLIGENCE ====================

function Get-GeoIPInfo {
    param([string]$IPAddress)
    
    if ($IPAddress -match "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") {
        return @{
            IP          = $IPAddress
            Country     = "Local/Private"
            CountryCode = "XX"
            City        = "Internal Network"
            Region      = "N/A"
            ISP         = "Private Network"
            Org         = "Internal"
            Timezone    = "N/A"
            Latitude    = 0
            Longitude   = 0
            IsPrivate   = $true
        }
    }
    
    try {
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$IPAddress`?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query" -TimeoutSec 10
        
        if ($response.status -eq "success") {
            return @{
                IP          = $response.query
                Country     = $response.country
                CountryCode = $response.countryCode
                City        = $response.city
                Region      = $response.regionName
                ISP         = $response.isp
                Org         = $response.org
                AS          = $response.as
                Timezone    = $response.timezone
                Latitude    = $response.lat
                Longitude   = $response.lon
                ZipCode     = $response.zip
                IsPrivate   = $false
            }
        }
    }
    catch {
        Write-SecurityLog -LogType "Alert" -Message "GeoIP lookup failed for $IPAddress" -Severity "WARNING" -Data @{IP = $IPAddress; Error = $_.Exception.Message}
    }
    
    return @{
        IP          = $IPAddress
        Country     = "Unknown"
        CountryCode = "??"
        City        = "Unknown"
        Region      = "Unknown"
        ISP         = "Unknown"
        IsPrivate   = $false
    }
}

# ==================== RDP CONNECTION MONITORING ====================

function Get-RDPConnections {
    $results = @()
    $startTime = (Get-Date).AddHours(-24)
    
    try {
        $successfulLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4624
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties[8].Value -eq 10
        }
        
        foreach ($event in $successfulLogons) {
            $results += [PSCustomObject]@{
                EventType    = "SuccessfulLogon"
                TimeCreated  = $event.TimeCreated
                Username     = $event.Properties[5].Value
                Domain       = $event.Properties[6].Value
                SourceIP     = $event.Properties[18].Value
                LogonType    = $event.Properties[8].Value
                LogonID      = $event.Properties[7].Value
                ProcessName  = $event.Properties[17].Value
                EventID      = 4624
            }
        }
        
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties[10].Value -eq 10
        }
        
        foreach ($event in $failedLogons) {
            $results += [PSCustomObject]@{
                EventType       = "FailedLogon"
                TimeCreated     = $event.TimeCreated
                Username        = $event.Properties[5].Value
                Domain          = $event.Properties[6].Value
                SourceIP        = $event.Properties[19].Value
                FailureReason   = $event.Properties[8].Value
                SubStatus       = $event.Properties[9].Value
                LogonType       = $event.Properties[10].Value
                EventID         = 4625
            }
        }
    }
    catch {
        Write-SecurityLog -LogType "Alert" -Message "Security log okuma hatasi" -Severity "WARNING" -Data @{Error = $_.Exception.Message}
    }
    
    try {
        $tsEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        foreach ($event in $tsEvents) {
            $eventType = switch ($event.Id) {
                21 { "SessionLogon" }
                22 { "ShellStart" }
                23 { "SessionLogoff" }
                24 { "SessionDisconnect" }
                25 { "SessionReconnect" }
                default { "Unknown" }
            }
            
            if ($eventType -ne "Unknown") {
                $xml = [xml]$event.ToXml()
                $userData = $xml.Event.UserData.EventXML
                
                $results += [PSCustomObject]@{
                    EventType    = $eventType
                    TimeCreated  = $event.TimeCreated
                    Username     = $userData.User
                    SessionID    = $userData.SessionID
                    SourceIP     = $userData.Address
                    EventID      = $event.Id
                }
            }
        }
    }
    catch {
        Write-SecurityLog -LogType "Alert" -Message "Terminal Services log okuma hatasi" -Severity "WARNING" -Data @{Error = $_.Exception.Message}
    }
    
    return $results | Sort-Object TimeCreated -Descending
}

# ==================== SESSION MONITORING ====================

function Get-ActiveRDPSessions {
    $sessions = @()
    
    try {
        $quserOutput = quser 2>$null
        
        if ($quserOutput) {
            $quserOutput | Select-Object -Skip 1 | ForEach-Object {
                $line = $_ -replace '\s{2,}', ','
                $parts = $line.Split(',')
                
                if ($parts.Count -ge 4) {
                    $sessions += [PSCustomObject]@{
                        Username    = $parts[0].Trim()
                        SessionName = $parts[1].Trim()
                        SessionID   = $parts[2].Trim()
                        State       = $parts[3].Trim()
                        IdleTime    = if ($parts.Count -ge 5) { $parts[4].Trim() } else { "N/A" }
                        LogonTime   = if ($parts.Count -ge 6) { $parts[5..($parts.Count-1)] -join ' ' } else { "N/A" }
                    }
                }
            }
        }
        
        $wmiSessions = Get-CimInstance -ClassName Win32_LogonSession | Where-Object { $_.LogonType -eq 10 }
        
        foreach ($wmiSession in $wmiSessions) {
            $loggedOnUser = Get-CimAssociatedInstance -InputObject $wmiSession -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue
            
            if ($loggedOnUser) {
                $existingSession = $sessions | Where-Object { $_.Username -like "*$($loggedOnUser.Name)*" }
                if ($existingSession) {
                    $existingSession | Add-Member -NotePropertyName "LogonID" -NotePropertyValue $wmiSession.LogonId -Force
                    $existingSession | Add-Member -NotePropertyName "StartTime" -NotePropertyValue $wmiSession.StartTime -Force
                    $existingSession | Add-Member -NotePropertyName "AuthPackage" -NotePropertyValue $wmiSession.AuthenticationPackage -Force
                }
            }
        }
    }
    catch {
        Write-SecurityLog -LogType "Alert" -Message "Session bilgisi alma hatasi" -Severity "WARNING" -Data @{Error = $_.Exception.Message}
    }
    
    return $sessions
}

function Get-SessionDuration {
    param([string]$Username)
    
    $sessions = Get-ActiveRDPSessions | Where-Object { $_.Username -eq $Username }
    
    foreach ($session in $sessions) {
        if ($session.StartTime) {
            $duration = (Get-Date) - $session.StartTime
            $session | Add-Member -NotePropertyName "Duration" -NotePropertyValue $duration -Force
            $session | Add-Member -NotePropertyName "DurationFormatted" -NotePropertyValue ("{0:dd\.hh\:mm\:ss}" -f $duration) -Force
        }
    }
    
    return $sessions
}

# ==================== PROCESS MONITORING ====================

function Get-UserProcesses {
    param([string]$Username)
    
    $processes = @()
    
    try {
        $userProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
            Where-Object { $_.UserName -like "*$Username*" }
        
        foreach ($proc in $userProcesses) {
            $processes += [PSCustomObject]@{
                ProcessName     = $proc.ProcessName
                ProcessID       = $proc.Id
                CPU             = [math]::Round($proc.CPU, 2)
                MemoryMB        = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                StartTime       = $proc.StartTime
                Path            = $proc.Path
                CommandLine     = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                Username        = $proc.UserName
                WindowTitle     = $proc.MainWindowTitle
            }
        }
    }
    catch {
        Write-SecurityLog -LogType "Alert" -Message "Process bilgisi alma hatasi" -Severity "WARNING" -Data @{Error = $_.Exception.Message; Username = $Username}
    }
    
    return $processes
}

function Watch-ProcessActivity {
    param(
        [int]$IntervalSeconds = 30,
        [scriptblock]$OnNewProcess,
        [scriptblock]$OnProcessExit
    )
    
    $knownProcesses = @{}
    
    while ($true) {
        $sessions = Get-ActiveRDPSessions
        
        foreach ($session in $sessions) {
            $currentProcesses = Get-UserProcesses -Username $session.Username
            $sessionKey = "$($session.Username)_$($session.SessionID)"
            
            if (-not $knownProcesses.ContainsKey($sessionKey)) {
                $knownProcesses[$sessionKey] = @{}
            }
            
            foreach ($proc in $currentProcesses) {
                $procKey = "$($proc.ProcessName)_$($proc.ProcessID)"
                
                if (-not $knownProcesses[$sessionKey].ContainsKey($procKey)) {
                    $knownProcesses[$sessionKey][$procKey] = $proc
                    
                    Write-SecurityLog -LogType "Activity" -Message "New process started" -Severity "INFO" -Data @{
                        Username    = $session.Username
                        SessionID   = $session.SessionID
                        Process     = $proc.ProcessName
                        ProcessID   = $proc.ProcessID
                        Path        = $proc.Path
                        CommandLine = $proc.CommandLine
                        StartTime   = $proc.StartTime
                    }
                    
                    if ($OnNewProcess) { & $OnNewProcess $proc }
                }
            }
            
            $currentProcKeys = $currentProcesses | ForEach-Object { "$($_.ProcessName)_$($_.ProcessID)" }
            $exitedProcs = $knownProcesses[$sessionKey].Keys | Where-Object { $_ -notin $currentProcKeys }
            
            foreach ($exitedKey in $exitedProcs) {
                $exitedProc = $knownProcesses[$sessionKey][$exitedKey]
                
                Write-SecurityLog -LogType "Activity" -Message "Process exited" -Severity "INFO" -Data @{
                    Username  = $session.Username
                    SessionID = $session.SessionID
                    Process   = $exitedProc.ProcessName
                    ProcessID = $exitedProc.ProcessID
                    RunTime   = if ($exitedProc.StartTime) { ((Get-Date) - $exitedProc.StartTime).ToString() } else { "Unknown" }
                }
                
                $knownProcesses[$sessionKey].Remove($exitedKey)
                if ($OnProcessExit) { & $OnProcessExit $exitedProc }
            }
        }
        
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# ==================== BRUTE FORCE DETECTION ====================

function Get-FailedLoginAnalysis {
    param(
        [int]$TimeWindowMinutes = 60,
        [int]$Threshold = 5
    )
    
    $startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)
    $failedLogins = @{}
    $alerts = @()
    
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        foreach ($event in $events) {
            $sourceIP = $event.Properties[19].Value
            $username = $event.Properties[5].Value
            $key = "$sourceIP|$username"
            
            if (-not $failedLogins.ContainsKey($key)) {
                $failedLogins[$key] = @{
                    IP        = $sourceIP
                    Username  = $username
                    Count     = 0
                    FirstSeen = $event.TimeCreated
                    LastSeen  = $event.TimeCreated
                    Attempts  = @()
                }
            }
            
            $failedLogins[$key].Count++
            $failedLogins[$key].LastSeen = $event.TimeCreated
            $failedLogins[$key].Attempts += @{
                Time   = $event.TimeCreated
                Reason = $event.Properties[8].Value
            }
        }
        
        foreach ($key in $failedLogins.Keys) {
            $entry = $failedLogins[$key]
            
            if ($entry.Count -ge $Threshold) {
                $geoInfo = Get-GeoIPInfo -IPAddress $entry.IP
                
                $alert = @{
                    Type           = "BruteForceAttempt"
                    IP             = $entry.IP
                    Username       = $entry.Username
                    AttemptCount   = $entry.Count
                    FirstAttempt   = $entry.FirstSeen
                    LastAttempt    = $entry.LastSeen
                    Country        = $geoInfo.Country
                    CountryCode    = $geoInfo.CountryCode
                    City           = $geoInfo.City
                    ISP            = $geoInfo.ISP
                    TimeWindow     = "$TimeWindowMinutes minutes"
                    Severity       = if ($entry.Count -ge ($Threshold * 3)) { "CRITICAL" } elseif ($entry.Count -ge ($Threshold * 2)) { "HIGH" } else { "MEDIUM" }
                }
                
                $alerts += $alert
                Write-SecurityLog -LogType "Alert" -Message "Brute force attempt detected from $($entry.IP)" -Severity $alert.Severity -Data $alert
            }
        }
    }
    catch {
        Write-SecurityLog -LogType "Alert" -Message "Failed login analysis error" -Severity "WARNING" -Data @{Error = $_.Exception.Message}
    }
    
    return @{
        Summary      = $failedLogins
        Alerts       = $alerts
        TimeWindow   = $TimeWindowMinutes
        Threshold    = $Threshold
        AnalyzedFrom = $startTime
        AnalyzedTo   = Get-Date
    }
}

# ==================== ALERTING ====================

function Send-Alert {
    param(
        [string]$Title,
        [string]$Message,
        [hashtable]$Data,
        [string]$Severity = "INFO"
    )
    
    $alertData = @{
        Title     = $Title
        Message   = $Message
        Severity  = $Severity
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Data      = $Data
        Server    = $env:COMPUTERNAME
    }
    
    Write-SecurityLog -LogType "Alert" -Message $Title -Severity $Severity -Data $alertData
    
    if ($Config.EnableTelegramAlert) {
        try {
            $emoji = switch ($Severity) {
                "CRITICAL" { "[!!!]" }
                "HIGH"     { "[!!]" }
                "WARNING"  { "[!]" }
                "INFO"     { "[i]" }
                default    { "[*]" }
            }
            
            $dataText = ""
            if ($Data) {
                foreach ($key in $Data.Keys) {
                    $value = $Data[$key]
                    if ($value -and $value -ne "Unknown" -and $value -ne "N/A") {
                        $keyStr = $key.ToString()
                        $valStr = $value.ToString()
                        $dataText += "`n- $keyStr : $valStr"
                    }
                }
            }
            
            $telegramMessage = @"
$emoji RDP Security Alert $emoji
========================
Server: $env:COMPUTERNAME
Time: $($alertData.Timestamp)
Severity: $Severity

$Title

$Message
$dataText
========================
"@
            
            $telegramUrl = "https://api.telegram.org/bot$($Config.TelegramBotToken)/sendMessage"
            $telegramBody = @{
                chat_id    = $Config.TelegramChatID
                text       = $telegramMessage
            }
            
            Invoke-RestMethod -Uri $telegramUrl -Method Post -Body $telegramBody -TimeoutSec 10 | Out-Null
            Write-Host "[+] Telegram alert gonderildi: $Title" -ForegroundColor Green
        }
        catch {
            Write-SecurityLog -LogType "Alert" -Message "Telegram gonderimi basarisiz" -Severity "WARNING" -Data @{Error = $_.Exception.Message}
            Write-Host "[-] Telegram alert gonderilemedi: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ==================== REPORTING ====================

function New-DailyReport {
    $reportDate = Get-Date -Format "yyyy-MM-dd"
    $reportPath = Join-Path $Config.ReportPath "daily_report_$reportDate.html"
    
    $connections = Get-RDPConnections
    $successfulLogons = $connections | Where-Object { $_.EventType -eq "SuccessfulLogon" }
    $failedLogons = $connections | Where-Object { $_.EventType -eq "FailedLogon" }
    $sessions = Get-ActiveRDPSessions
    $bruteForceAnalysis = Get-FailedLoginAnalysis -TimeWindowMinutes 1440
    
    $uniqueIPs = ($connections | Select-Object -ExpandProperty SourceIP -Unique) | Where-Object { $_ }
    $geoData = @{}
    foreach ($ip in $uniqueIPs) {
        if ($ip -and $ip -ne "-") {
            $geoData[$ip] = Get-GeoIPInfo -IPAddress $ip
        }
    }
    
    $successTableRows = ""
    $successfulLogons | Select-Object -First 50 | ForEach-Object {
        $geo = $geoData[$_.SourceIP]
        $geoCountry = if ($geo) { $geo.Country } else { "Unknown" }
        $geoCity = if ($geo) { $geo.City } else { "Unknown" }
        $geoISP = if ($geo) { $geo.ISP } else { "Unknown" }
        $successTableRows += "<tr><td>$($_.TimeCreated)</td><td>$($_.Domain)\$($_.Username)</td><td>$($_.SourceIP)</td><td>$geoCountry, $geoCity</td><td>$geoISP</td></tr>`n"
    }
    
    $failedTableRows = ""
    $failedLogons | Select-Object -First 50 | ForEach-Object {
        $geo = $geoData[$_.SourceIP]
        $geoCountry = if ($geo) { $geo.Country } else { "Unknown" }
        $geoCity = if ($geo) { $geo.City } else { "Unknown" }
        $geoISP = if ($geo) { $geo.ISP } else { "Unknown" }
        $failedTableRows += "<tr><td>$($_.TimeCreated)</td><td>$($_.Domain)\$($_.Username)</td><td>$($_.SourceIP)</td><td>$geoCountry, $geoCity</td><td>$geoISP</td></tr>`n"
    }
    
    $sessionTableRows = ""
    $sessions | ForEach-Object {
        $sessionTableRows += "<tr><td>$($_.Username)</td><td>$($_.SessionID)</td><td>$($_.State)</td><td>$($_.IdleTime)</td><td>$($_.LogonTime)</td></tr>`n"
    }
    
    $alertsHtml = ""
    if ($bruteForceAnalysis.Alerts.Count -gt 0) {
        $bruteForceAnalysis.Alerts | ForEach-Object {
            $alertsHtml += "<div class='alert-box'><strong>$($_.Type)</strong>: $($_.IP) ($($_.Country)) - $($_.AttemptCount) attempts</div>`n"
        }
    } else {
        $alertsHtml = "<p>No brute-force attacks detected in the last 24 hours.</p>"
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RDP Security Report - $reportDate</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary-cards { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .card { flex: 1; min-width: 200px; padding: 20px; border-radius: 8px; color: white; }
        .card-success { background: #27ae60; }
        .card-danger { background: #c0392b; }
        .card-warning { background: #f39c12; }
        .card-info { background: #2980b9; }
        .card h3 { margin: 0; font-size: 2em; }
        .card p { margin: 5px 0 0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        tr:hover { background: #f8f9fa; }
        .alert-box { padding: 15px; border-radius: 5px; margin: 10px 0; background: #fadbd8; border-left: 4px solid #c0392b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RDP Security Intelligence Report</h1>
        <p>Server: $env:COMPUTERNAME | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
        <div class="summary-cards">
            <div class="card card-success"><h3>$($successfulLogons.Count)</h3><p>Successful Logins</p></div>
            <div class="card card-danger"><h3>$($failedLogons.Count)</h3><p>Failed Attempts</p></div>
            <div class="card card-info"><h3>$($sessions.Count)</h3><p>Active Sessions</p></div>
            <div class="card card-warning"><h3>$($bruteForceAnalysis.Alerts.Count)</h3><p>Security Alerts</p></div>
        </div>

        <h2>Security Alerts</h2>
        $alertsHtml

        <h2>Successful Logins</h2>
        <table>
            <tr><th>Time</th><th>User</th><th>IP Address</th><th>Location</th><th>ISP</th></tr>
            $successTableRows
        </table>

        <h2>Failed Attempts</h2>
        <table>
            <tr><th>Time</th><th>User</th><th>IP Address</th><th>Location</th><th>ISP</th></tr>
            $failedTableRows
        </table>

        <h2>Active Sessions</h2>
        <table>
            <tr><th>User</th><th>Session ID</th><th>State</th><th>Idle</th><th>Logon Time</th></tr>
            $sessionTableRows
        </table>

        <hr><p>Generated by RDP Security Intelligence System</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-SecurityLog -LogType "Alert" -Message "Daily report generated" -Severity "INFO" -Data @{Path = $reportPath}
    return $reportPath
}

# ==================== MONITORING SERVICE ====================

function Start-RDPMonitoringService {
    param([switch]$Verbose)
    
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "       RDP Security Intelligence Monitoring System" -ForegroundColor Yellow
    Write-Host "                  v2.0 by Furkan Dincer" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "[+] Connection Monitoring    [+] GeoIP Intelligence" -ForegroundColor Green
    Write-Host "[+] Session Tracking         [+] Brute Force Detection" -ForegroundColor Green
    Write-Host "[+] Process Activity         [+] Real-time Alerting" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    
    Initialize-LogDirectories
    $lastEventTime = Get-Date
    
    while ($true) {
        try {
            $newEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                ID        = @(4624, 4625)
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue | Where-Object {
                ($_.Properties[8].Value -eq 10) -or ($_.Properties[10].Value -eq 10)
            }
            
            foreach ($event in $newEvents) {
                $isSuccess = $event.Id -eq 4624
                $sourceIP = if ($isSuccess) { $event.Properties[18].Value } else { $event.Properties[19].Value }
                $username = $event.Properties[5].Value
                $domain = $event.Properties[6].Value
                
                $geoInfo = Get-GeoIPInfo -IPAddress $sourceIP
                
                $eventData = @{
                    EventType    = if ($isSuccess) { "SuccessfulLogon" } else { "FailedLogon" }
                    Timestamp    = $event.TimeCreated
                    Username     = "$domain\$username"
                    SourceIP     = $sourceIP
                    Country      = $geoInfo.Country
                    CountryCode  = $geoInfo.CountryCode
                    City         = $geoInfo.City
                    ISP          = $geoInfo.ISP
                    Organization = $geoInfo.Org
                }
                
                $severity = if ($isSuccess) { "INFO" } else { "WARNING" }
                $message = if ($isSuccess) { 
                    "RDP login: $domain\$username from $sourceIP ($($geoInfo.Country), $($geoInfo.City))"
                } else {
                    "Failed RDP: $domain\$username from $sourceIP ($($geoInfo.Country), $($geoInfo.City))"
                }
                
                Write-SecurityLog -LogType "Connection" -Message $message -Severity $severity -Data $eventData
                
                if ($isSuccess) {
                    Send-Alert -Title "RDP Giris Yapildi" -Message "$domain\$username baglandi" -Data @{
                        Kullanici = "$domain\$username"
                        IP = $sourceIP
                        Ulke = $geoInfo.Country
                        Sehir = $geoInfo.City
                        ISP = $geoInfo.ISP
                        Zaman = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    } -Severity "INFO"
                } else {
                    Send-Alert -Title "Basarisiz RDP Denemesi" -Message "$domain\$username giris yapamadi" -Data @{
                        Kullanici = "$domain\$username"
                        IP = $sourceIP
                        Ulke = $geoInfo.Country
                        Sehir = $geoInfo.City
                        ISP = $geoInfo.ISP
                        Zaman = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    } -Severity "WARNING"
                }
                
                if ($geoInfo.CountryCode -in $Config.SuspiciousCountries) {
                    Send-Alert -Title "SUPHELI ULKE UYARISI" -Message "Tehlikeli bolgeden baglanti denemesi!" -Data $eventData -Severity "CRITICAL"
                }
            }
            
            if ($newEvents) {
                $lastEventTime = ($newEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.AddSeconds(1)
            }
            
            if ((Get-Date).Minute % 5 -eq 0 -and (Get-Date).Second -lt 10) {
                $bruteForce = Get-FailedLoginAnalysis -TimeWindowMinutes $([math]::Ceiling($Config.FailedLoginTimeWindow / 60)) -Threshold $Config.FailedLoginThreshold
                foreach ($alert in $bruteForce.Alerts) {
                    Send-Alert -Title "Brute Force Saldirisi Tespit Edildi" -Message "Coklu basarisiz giris: $($alert.IP)" -Data $alert -Severity $alert.Severity
                }
            }
            
            if ((Get-Date).Minute % 5 -eq 0 -and (Get-Date).Second -lt 10) {
                $sessions = Get-ActiveRDPSessions
                foreach ($session in $sessions) {
                    $processes = Get-UserProcesses -Username $session.Username
                    Write-SecurityLog -LogType "Session" -Message "Active session: $($session.Username)" -Severity "INFO" -Data @{
                        Username = $session.Username
                        SessionID = $session.SessionID
                        State = $session.State
                        ProcessCount = $processes.Count
                    }
                }
            }
        }
        catch {
            Write-SecurityLog -LogType "Alert" -Message "Monitoring error" -Severity "WARNING" -Data @{Error = $_.Exception.Message}
        }
        
        Start-Sleep -Seconds 5
    }
}

# ==================== SCHEDULED TASKS ====================

function Install-MonitoringScheduledTasks {
    Write-Host "[*] Scheduled Task'lar kuruluyor..." -ForegroundColor Yellow
    
    $scriptDestination = "C:\RDP-Security-Logs\RDP-Security-Intelligence.ps1"
    $currentScript = $PSScriptRoot + "\RDP-Security-Intelligence.ps1"
    
    if (-not (Test-Path "C:\RDP-Security-Logs")) {
        New-Item -ItemType Directory -Path "C:\RDP-Security-Logs" -Force | Out-Null
    }
    
    if (Test-Path $currentScript) {
        Copy-Item -Path $currentScript -Destination $scriptDestination -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Script kopyalandi: $scriptDestination" -ForegroundColor Green
    } else {
        Write-Host "[!] Mevcut script bulunamadi, hedef path kullaniliyor" -ForegroundColor Yellow
    }
    
    $monitoringAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `". '$scriptDestination'; Start-RDPMonitoringService`""
    
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999))
    )
    
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 9999) -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    Register-ScheduledTask -TaskName "RDP Security Monitoring Service" -Action $monitoringAction -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "[+] Monitoring Service kuruldu (7/24)" -ForegroundColor Green
    
    $reportAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& {. '$scriptDestination'; New-DailyReport}`""
    $reportTrigger = New-ScheduledTaskTrigger -Daily -At "23:55"
    Register-ScheduledTask -TaskName "RDP Security Daily Report" -Action $reportAction -Trigger $reportTrigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "[+] Daily Report kuruldu (23:55)" -ForegroundColor Green
    
    $cleanupAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Get-ChildItem -Path 'C:\RDP-Security-Logs' -Recurse -File | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-$($Config.LogRetentionDays)) } | Remove-Item -Force`""
    $cleanupTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "03:00"
    Register-ScheduledTask -TaskName "RDP Security Log Cleanup" -Action $cleanupAction -Trigger $cleanupTrigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "[+] Log Cleanup kuruldu (Pazar 03:00)" -ForegroundColor Green
    
    try {
        Start-ScheduledTask -TaskName "RDP Security Monitoring Service" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } catch {
        Write-Host "[!] Task baslatilirken hata: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    try {
        $taskState = (Get-ScheduledTask -TaskName "RDP Security Monitoring Service" -ErrorAction SilentlyContinue).State
        if ($taskState -eq "Running") {
            Write-Host "[+] Servis CALISIYOR!" -ForegroundColor Green
        } else {
            Write-Host "[!] Servis durumu: $taskState" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Servis durumu kontrolu basarisiz" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                 KURULUM TAMAMLANDI!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "[+] 7/24 Monitoring Aktif" -ForegroundColor Green
    Write-Host "[+] Sunucu restart sonrasi otomatik baslar" -ForegroundColor Green
    Write-Host "[+] Cokerse 1 dk icinde yeniden baslar" -ForegroundColor Green
    Write-Host "[+] Her gun 23:55'te rapor olusturulur" -ForegroundColor Green
    Write-Host "[+] 90 gunden eski loglar silinir" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
}

# ==================== UTILITY FUNCTIONS ====================

function Get-QuickSecurityStatus {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "            RDP SECURITY QUICK STATUS" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    
    $connections = Get-RDPConnections
    $successful = ($connections | Where-Object { $_.EventType -eq "SuccessfulLogon" }).Count
    $failed = ($connections | Where-Object { $_.EventType -eq "FailedLogon" }).Count
    $sessions = Get-ActiveRDPSessions
    $bruteForce = Get-FailedLoginAnalysis -TimeWindowMinutes 60 -Threshold 3
    
    Write-Host ""
    Write-Host "Son 24 Saat:" -ForegroundColor White
    Write-Host "   [+] Basarili Giris : $successful" -ForegroundColor Green
    Write-Host "   [-] Basarisiz      : $failed" -ForegroundColor Red
    Write-Host "   [*] Aktif Oturum   : $($sessions.Count)" -ForegroundColor Cyan
    Write-Host "   [!] Uyari          : $($bruteForce.Alerts.Count)" -ForegroundColor Yellow
    
    if ($sessions.Count -gt 0) {
        Write-Host ""
        Write-Host "Aktif Oturumlar:" -ForegroundColor White
        foreach ($s in $sessions) { 
            Write-Host "   - $($s.Username) (ID: $($s.SessionID), $($s.State))" -ForegroundColor Cyan 
        }
    }
    
    if ($bruteForce.Alerts.Count -gt 0) {
        Write-Host ""
        Write-Host "Uyarilar:" -ForegroundColor Red
        foreach ($a in $bruteForce.Alerts) { 
            Write-Host "   [!] $($a.IP) ($($a.Country)) - $($a.AttemptCount) deneme" -ForegroundColor Yellow 
        }
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Test-TelegramConnection {
    Write-Host ""
    Write-Host "[*] Telegram baglantisi test ediliyor..." -ForegroundColor Yellow
    
    try {
        $msg = "[TEST] RDP Security`n`nServer: $env:COMPUTERNAME`nTime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`nBaglanti basarili!"
        $url = "https://api.telegram.org/bot$($Config.TelegramBotToken)/sendMessage"
        $body = @{ chat_id = $Config.TelegramChatID; text = $msg }
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -TimeoutSec 10
        
        if ($response.ok) {
            Write-Host "[+] Telegram OK! Test mesaji gonderildi." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "[-] Telegram BASARISIZ: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-MonitoringServiceStatus {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "         MONITORING SERVICE STATUS" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    
    $tasks = @("RDP Security Monitoring Service", "RDP Security Daily Report", "RDP Security Log Cleanup")
    
    foreach ($taskName in $tasks) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                $info = Get-ScheduledTaskInfo -TaskName $taskName
                $status = switch ($task.State) {
                    "Running"  { "[+] CALISIYOR" }
                    "Ready"    { "[*] HAZIR" }
                    "Disabled" { "[-] DEVRE DISI" }
                    default    { "[?] $($task.State)" }
                }
                Write-Host ""
                Write-Host "Task: $taskName" -ForegroundColor White
                Write-Host "   Durum: $status" -ForegroundColor $(if ($task.State -eq "Running") { "Green" } else { "Yellow" })
                Write-Host "   Son Calisma: $($info.LastRunTime)" -ForegroundColor Gray
                Write-Host "   Sonraki: $($info.NextRunTime)" -ForegroundColor Gray
            } else {
                Write-Host ""
                Write-Host "Task: $taskName : [-] KURULU DEGIL" -ForegroundColor Red
            }
        } catch {
            Write-Host ""
            Write-Host "Task: $taskName : [-] HATA" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Log Dizini:" -ForegroundColor White
    if (Test-Path $Config.LogBasePath) {
        $size = (Get-ChildItem -Path $Config.LogBasePath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
        $count = (Get-ChildItem -Path $Config.LogBasePath -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "   Konum: $($Config.LogBasePath)" -ForegroundColor Gray
        Write-Host "   Boyut: $([math]::Round($size, 2)) MB ($count dosya)" -ForegroundColor Gray
    } else {
        Write-Host "   [-] Bulunamadi" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
}

# ==================== MAIN ====================

if ($MyInvocation.InvocationName -ne '.') {
    if ($args -contains "-StartMonitoring") {
        Start-RDPMonitoringService
        exit
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "       RDP Security Intelligence System v2.0" -ForegroundColor Yellow
    Write-Host "                  by Furkan Dincer" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "KOMUTLAR:" -ForegroundColor White
    Write-Host "  . .\RDP-Security-Intelligence.ps1  # Script'i yukle" -ForegroundColor Gray
    Write-Host "  Test-TelegramConnection           # Telegram test" -ForegroundColor Gray
    Write-Host "  Install-MonitoringScheduledTasks  # Servisi kur" -ForegroundColor Gray
    Write-Host "  Get-MonitoringServiceStatus       # Servis durumu" -ForegroundColor Gray
    Write-Host "  Get-QuickSecurityStatus           # Hizli ozet" -ForegroundColor Gray
    Write-Host "  Get-RDPConnections                # Son 24 saat" -ForegroundColor Gray
    Write-Host "  New-DailyReport                   # HTML rapor" -ForegroundColor Gray
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
}
