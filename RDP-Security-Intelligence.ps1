<#
.SYNOPSIS
    RDP Security Intelligence & Ultra Monitoring System v3.0
    Kapsamli RDP Guvenlik Izleme, Koruma ve Raporlama Sistemi
    
.DESCRIPTION
    Bu script asagidaki ozellikleri saglar:
    
    [IZLEME]
    - Tum RDP baglantilarini loglar (basarili/basarisiz)
    - IP adresinden GeoIP bilgisi ceker (ulke, sehir, ISP)
    - Oturum suresini takip eder
    - Kullanici aktivitelerini kaydeder
    - Supheli process tespiti (mimikatz, psexec vb.)
    
    [KORUMA]
    - Brute-force saldiri tespiti ve otomatik IP engelleme
    - Windows Firewall entegrasyonu
    - Whitelist destegi (CIDR notation)
    - Rate limiting
    - Supheli ulke uyarilari
    
    [RAPORLAMA]
    - Real-time Telegram bildirimleri
    - Detayli gunluk HTML raporlar
    - Kapsamli haftalik HTML raporlar
    - Hedeflenen kullanici adi analizi
    
.AUTHOR
    Furkan Dincer
    
.VERSION
    3.0.0
    
.LINK
    https://github.com/furkandncer/RDP-Security-Intelligence
    
.NOTES
    Windows Server 2012 R2/2016/2019/2022/2025 uyumlu
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
    BlockedIPsPath      = "C:\RDP-Security-Logs\BlockedIPs"
    
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
    
    # Otomatik IP Engelleme
    EnableAutoBlock         = $true
    AutoBlockThreshold      = 10
    AutoBlockDurationDays   = 30
    
    # Whitelist - Bu IP'lerden alert gelmesin
    WhitelistIPs            = @("192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12")
    WhitelistEnabled        = $true
    
    # Supheli Process Listesi
    SuspiciousProcesses     = @("mimikatz", "psexec", "procdump", "lazagne", "secretsdump", "wce", "fgdump", "pwdump", "gsecdump", "lsass")
    
    # Rate Limiting
    RateLimitPerMinute      = 20
    RateLimitAlertEnabled   = $true
    
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
        $Config.ReportPath,
        $Config.BlockedIPsPath
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

# ==================== WHITELIST FUNCTIONS ====================

function Test-WhitelistedIP {
    param([string]$IPAddress)
    
    if (-not $Config.WhitelistEnabled) { return $false }
    
    foreach ($entry in $Config.WhitelistIPs) {
        if ($entry -match "/") {
            # CIDR notation
            $parts = $entry -split "/"
            $network = $parts[0]
            $prefix = [int]$parts[1]
            
            try {
                $ipBytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
                $netBytes = ([System.Net.IPAddress]::Parse($network)).GetAddressBytes()
                
                [Array]::Reverse($ipBytes)
                [Array]::Reverse($netBytes)
                
                $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
                $netInt = [BitConverter]::ToUInt32($netBytes, 0)
                $mask = [UInt32]::MaxValue -shl (32 - $prefix)
                
                if (($ipInt -band $mask) -eq ($netInt -band $mask)) {
                    return $true
                }
            }
            catch { }
        }
        else {
            # Single IP
            if ($IPAddress -eq $entry) { return $true }
        }
    }
    
    return $false
}

function Add-WhitelistIP {
    param([string]$IPAddress)
    
    if ($IPAddress -notin $Config.WhitelistIPs) {
        $Config.WhitelistIPs += $IPAddress
        Write-Host "[+] Whitelist'e eklendi: $IPAddress" -ForegroundColor Green
        return $true
    }
    Write-Host "[!] IP zaten whitelist'te: $IPAddress" -ForegroundColor Yellow
    return $false
}

function Remove-WhitelistIP {
    param([string]$IPAddress)
    
    $Config.WhitelistIPs = $Config.WhitelistIPs | Where-Object { $_ -ne $IPAddress }
    Write-Host "[+] Whitelist'ten cikarildi: $IPAddress" -ForegroundColor Green
}

function Get-WhitelistIPs {
    Write-Host ""
    Write-Host "=== WHITELIST IP'LER ===" -ForegroundColor Cyan
    Write-Host "Durum: $(if ($Config.WhitelistEnabled) { 'AKTIF' } else { 'PASIF' })" -ForegroundColor $(if ($Config.WhitelistEnabled) { "Green" } else { "Red" })
    Write-Host ""
    foreach ($ip in $Config.WhitelistIPs) {
        Write-Host "  - $ip" -ForegroundColor White
    }
    Write-Host ""
}

# ==================== AUTO BLOCK FUNCTIONS ====================

function Block-IPAddress {
    param(
        [string]$IPAddress,
        [string]$Reason = "Brute-force attack",
        [int]$DurationDays = 30
    )
    
    if (Test-WhitelistedIP -IPAddress $IPAddress) {
        Write-Host "[!] IP whitelist'te, engellenmiyor: $IPAddress" -ForegroundColor Yellow
        return $false
    }
    
    $ruleName = "RDP-Security-Block-$IPAddress"
    
    # Zaten engelli mi kontrol et
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-Host "[!] IP zaten engelli: $IPAddress" -ForegroundColor Yellow
        return $false
    }
    
    try {
        # Firewall kurali olustur
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $IPAddress -Action Block -Protocol Any -Description "Blocked by RDP Security Intelligence - $Reason - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-Null
        
        # Log kaydet
        $blockLog = @{
            IP = $IPAddress
            Reason = $Reason
            BlockedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ExpiresAt = (Get-Date).AddDays($DurationDays).ToString("yyyy-MM-dd HH:mm:ss")
            DurationDays = $DurationDays
            RuleName = $ruleName
        }
        
        $blockLogFile = Join-Path $Config.BlockedIPsPath "blocked_ips.json"
        $blockLog | ConvertTo-Json -Compress | Add-Content -Path $blockLogFile -Encoding UTF8
        
        Write-Host "[+] IP ENGELLENDI: $IPAddress ($Reason)" -ForegroundColor Red
        Write-SecurityLog -LogType "Alert" -Message "IP blocked: $IPAddress" -Severity "CRITICAL" -Data $blockLog
        
        # Telegram bildir
        Send-Alert -Title "IP ENGELLENDI" -Message "$IPAddress firewall'a eklendi" -Data @{
            IP = $IPAddress
            Sebep = $Reason
            Sure = "$DurationDays gun"
        } -Severity "CRITICAL"
        
        return $true
    }
    catch {
        Write-Host "[-] IP engellenemedi: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Unblock-IPAddress {
    param([string]$IPAddress)
    
    $ruleName = "RDP-Security-Block-$IPAddress"
    
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        Write-Host "[+] IP engeli kaldirildi: $IPAddress" -ForegroundColor Green
        Write-SecurityLog -LogType "Alert" -Message "IP unblocked: $IPAddress" -Severity "INFO" -Data @{IP = $IPAddress}
        return $true
    }
    catch {
        Write-Host "[-] Engel kaldirilamadi: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-BlockedIPs {
    Write-Host ""
    Write-Host "=== ENGELLENEN IP'LER ===" -ForegroundColor Cyan
    
    $rules = Get-NetFirewallRule -DisplayName "RDP-Security-Block-*" -ErrorAction SilentlyContinue
    
    if ($rules) {
        foreach ($rule in $rules) {
            $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
            $ip = $filter.RemoteAddress
            $desc = $rule.Description
            Write-Host "  [X] $ip" -ForegroundColor Red
            Write-Host "      $desc" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "Toplam: $($rules.Count) IP engelli" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Engellenen IP yok" -ForegroundColor Green
    }
    Write-Host ""
}

function Clear-ExpiredBlocks {
    $blockLogFile = Join-Path $Config.BlockedIPsPath "blocked_ips.json"
    
    if (-not (Test-Path $blockLogFile)) { return }
    
    $now = Get-Date
    $cleared = 0
    
    Get-Content $blockLogFile | ForEach-Object {
        try {
            $entry = $_ | ConvertFrom-Json
            $expiresAt = [DateTime]::Parse($entry.ExpiresAt)
            
            if ($now -gt $expiresAt) {
                Unblock-IPAddress -IPAddress $entry.IP
                $cleared++
            }
        }
        catch { }
    }
    
    if ($cleared -gt 0) {
        Write-Host "[+] $cleared suresi dolmus engel kaldirildi" -ForegroundColor Green
    }
}

# ==================== RATE LIMITING ====================

$Script:RateLimitTracker = @{}

function Test-RateLimit {
    param([string]$IPAddress)
    
    if (-not $Config.RateLimitAlertEnabled) { return $false }
    
    $now = Get-Date
    $key = $IPAddress
    
    if (-not $Script:RateLimitTracker[$key]) {
        $Script:RateLimitTracker[$key] = @{
            Count = 0
            FirstSeen = $now
            Alerted = $false
        }
    }
    
    $tracker = $Script:RateLimitTracker[$key]
    
    # 1 dakikadan eski kayitlari sifirla
    if (($now - $tracker.FirstSeen).TotalMinutes -gt 1) {
        $tracker.Count = 0
        $tracker.FirstSeen = $now
        $tracker.Alerted = $false
    }
    
    $tracker.Count++
    
    if ($tracker.Count -ge $Config.RateLimitPerMinute -and -not $tracker.Alerted) {
        $tracker.Alerted = $true
        return $true  # Rate limit asildi
    }
    
    return $false
}

# ==================== SUSPICIOUS PROCESS DETECTION ====================

function Test-SuspiciousProcess {
    param([string]$ProcessName)
    
    $lowerName = $ProcessName.ToLower()
    foreach ($suspicious in $Config.SuspiciousProcesses) {
        if ($lowerName -match $suspicious) {
            return $true
        }
    }
    return $false
}

function Watch-UserProcesses {
    param([string]$Username)
    
    $processes = Get-UserProcesses -Username $Username
    $alerts = @()
    
    foreach ($proc in $processes) {
        if (Test-SuspiciousProcess -ProcessName $proc.ProcessName) {
            $alert = @{
                Username = $Username
                ProcessName = $proc.ProcessName
                ProcessID = $proc.ProcessID
                Path = $proc.Path
                CommandLine = $proc.CommandLine
                StartTime = $proc.StartTime
            }
            $alerts += $alert
            
            Send-Alert -Title "SUPHELI PROCESS TESPIT EDILDI" -Message "$Username kullanicisi supheli process calistirdi: $($proc.ProcessName)" -Data $alert -Severity "CRITICAL"
        }
    }
    
    return $alerts
}

# ==================== USERNAME ANALYSIS ====================

function Get-TargetedUsernames {
    param([int]$Hours = 24)
    
    $startTime = (Get-Date).AddHours(-$Hours)
    $usernameStats = @{}
    
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        foreach ($event in $events) {
            $username = $event.Properties[5].Value
            if ($username) {
                if (-not $usernameStats[$username]) {
                    $usernameStats[$username] = 0
                }
                $usernameStats[$username]++
            }
        }
    }
    catch { }
    
    return $usernameStats.GetEnumerator() | Sort-Object Value -Descending
}

function Show-TargetedUsernames {
    param([int]$Hours = 24, [int]$Top = 20)
    
    Write-Host ""
    Write-Host "=== EN COK HEDEFLENEN KULLANICI ADLARI (Son $Hours saat) ===" -ForegroundColor Cyan
    Write-Host ""
    
    $stats = Get-TargetedUsernames -Hours $Hours | Select-Object -First $Top
    $rank = 1
    
    foreach ($item in $stats) {
        $isCommon = $item.Key -in @("administrator", "admin", "sa", "root", "user", "guest", "test", "backup")
        $color = if ($isCommon) { "Yellow" } else { "Red" }
        $marker = if ($isCommon) { "[COMMON]" } else { "[!]" }
        
        Write-Host ("  {0,2}. {1,-25} : {2,6} deneme  $marker" -f $rank, $item.Key, $item.Value) -ForegroundColor $color
        $rank++
    }
    
    Write-Host ""
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
        
        # Basarisiz girisler - LogonType 3 (Network) ve 10 (RDP) dahil
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties[10].Value -in @(3, 10)
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
    param([DateTime]$TargetDate = (Get-Date))
    
    $reportDateStr = $TargetDate.ToString("yyyy-MM-dd")
    $reportPath = Join-Path $Config.ReportPath "daily_report_$reportDateStr.html"
    
    Write-Host "[*] Gunluk rapor hazirlaniyor: $reportDateStr" -ForegroundColor Cyan
    Write-Host "  - Event Log okunuyor..." -ForegroundColor Gray
    
    # --- VERI TOPLAMA ---
    # Tum failed logonlari al (LogonType 3 ve 10)
    $connections = Get-RDPConnections
    $successfulLogons = $connections | Where-Object { $_.EventType -eq "SuccessfulLogon" }
    $failedLogons = $connections | Where-Object { $_.EventType -eq "FailedLogon" }
    $sessions = Get-ActiveRDPSessions
    $bruteForceAnalysis = Get-FailedLoginAnalysis -TimeWindowMinutes 1440
    
    Write-Host "  - Basarili: $($successfulLogons.Count), Basarisiz: $($failedLogons.Count)" -ForegroundColor Gray
    Write-Host "  - GeoIP bilgileri aliniyor..." -ForegroundColor Gray
    
    # GeoIP bilgileri - sadece dis IP'ler icin
    $uniqueIPs = ($failedLogons | Select-Object -ExpandProperty SourceIP -Unique) | Where-Object { 
        $_ -and $_ -ne "-" -and $_ -notmatch "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
    }
    $geoData = @{}
    $ipCount = 0
    foreach ($ip in $uniqueIPs) {
        $ipCount++
        if ($ipCount % 10 -eq 0) { Write-Host "    - $ipCount / $($uniqueIPs.Count) IP..." -ForegroundColor DarkGray }
        $geoData[$ip] = Get-GeoIPInfo -IPAddress $ip
    }
    
    Write-Host "  - Analiz yapiliyor..." -ForegroundColor Gray
    
    # --- ISTATISTIKLER ---
    $successCount = $successfulLogons.Count
    $failedCount = $failedLogons.Count
    $alertCount = $bruteForceAnalysis.Alerts.Count
    $sessionCount = $sessions.Count
    
    # En cok saldiran IP'ler - GeoIP ile
    $ipStats = @{}
    foreach ($conn in $failedLogons) {
        $ip = $conn.SourceIP
        if ($ip -and $ip -ne "-") {
            if (-not $ipStats.ContainsKey($ip)) {
                # Onbellekte varsa kullan, yoksa sorgula
                $geo = if ($geoData.ContainsKey($ip)) { $geoData[$ip] } else { Get-GeoIPInfo -IPAddress $ip }
                $ipStats[$ip] = @{ 
                    Count = 0
                    Country = if ($geo.Country) { $geo.Country } else { "Unknown" }
                    City = if ($geo.City) { $geo.City } else { "Unknown" }
                    ISP = if ($geo.ISP) { $geo.ISP } else { "Unknown" }
                    CountryCode = if ($geo.CountryCode) { $geo.CountryCode } else { "??" }
                }
            }
            $ipStats[$ip].Count++
        }
    }
    $topAttackers = $ipStats.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 15
    $uniqueAttackerCount = $ipStats.Count
    
    Write-Host "  - $uniqueAttackerCount farkli IP, toplam $failedCount basarisiz giris" -ForegroundColor Gray
    
    # Ulke dagilimi
    $countryStats = @{}
    foreach ($ip in $ipStats.Keys) {
        $country = $ipStats[$ip].Country
        if ($country -and $country -ne "Unknown") {
            if (-not $countryStats.ContainsKey($country)) { $countryStats[$country] = 0 }
            $countryStats[$country] += $ipStats[$ip].Count
        }
    }
    $topCountries = $countryStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8
    $totalCountryAttempts = ($topCountries | Measure-Object -Property Value -Sum).Sum
    if ($totalCountryAttempts -eq 0) { $totalCountryAttempts = 1 }
    
    # Saatlik dagilim
    $hourlyStats = @{}
    for ($h = 0; $h -lt 24; $h++) { $hourlyStats[$h] = 0 }
    foreach ($conn in $failedLogons) {
        $hour = $conn.TimeCreated.Hour
        $hourlyStats[$hour]++
    }
    $maxHourly = ($hourlyStats.Values | Measure-Object -Maximum).Maximum
    if ($maxHourly -eq 0) { $maxHourly = 1 }
    
    # Hedeflenen kullanici adlari
    $userStats = @{}
    foreach ($conn in $failedLogons) {
        $user = $conn.Username
        if ($user) {
            if (-not $userStats.ContainsKey($user)) { $userStats[$user] = 0 }
            $userStats[$user]++
        }
    }
    $topUsers = $userStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    
    # --- HTML TABLO SATIRLARI ---
    
    # Top Attackers
    $topAttackersHtml = ""
    $rank = 1
    foreach ($attacker in $topAttackers) {
        $dangerClass = if ($attacker.Value.CountryCode -in @("CN", "RU", "KP", "IR", "BD")) { "danger-row" } else { "" }
        $topAttackersHtml += @"
        <tr class="$dangerClass">
            <td><span class="rank-badge">$rank</span></td>
            <td class="mono">$($attacker.Key)</td>
            <td>$($attacker.Value.Country)</td>
            <td class="desktop-only">$($attacker.Value.City)</td>
            <td class="desktop-only">$($attacker.Value.ISP)</td>
            <td class="text-right text-danger"><strong>$($attacker.Value.Count)</strong></td>
        </tr>
"@
        $rank++
    }
    if (-not $topAttackersHtml) {
        $topAttackersHtml = "<tr><td colspan='6' class='empty-row'>Son 24 saatte saldiri tespit edilmedi</td></tr>"
    }
    
    # Country distribution
    $countryBarsHtml = ""
    foreach ($country in $topCountries) {
        $percent = [math]::Round(($country.Value / $totalCountryAttempts) * 100)
        $countryBarsHtml += @"
        <div class="country-item">
            <div class="country-name">$($country.Key)</div>
            <div class="country-bar-container">
                <div class="country-bar" style="width: $percent%"></div>
            </div>
            <div class="country-count">$($country.Value)</div>
        </div>
"@
    }
    
    # Hourly chart
    $hourlyChartHtml = ""
    for ($h = 0; $h -lt 24; $h++) {
        $count = $hourlyStats[$h]
        $height = if ($count -gt 0) { [math]::Round(($count / $maxHourly) * 100) } else { 0 }
        $barClass = if ($count -gt ($maxHourly * 0.7)) { "bar-high" } elseif ($count -gt ($maxHourly * 0.3)) { "bar-medium" } else { "bar-low" }
        $hourlyChartHtml += @"
        <div class="hour-bar-wrapper">
            <div class="hour-value">$count</div>
            <div class="hour-bar $barClass" style="height: $(if($height -lt 3 -and $count -gt 0){3}else{$height})%"></div>
            <div class="hour-label">$('{0:D2}' -f $h)</div>
        </div>
"@
    }
    
    # Targeted usernames
    $targetedUsersHtml = ""
    $rank = 1
    foreach ($user in $topUsers) {
        $commonUsers = @("administrator", "admin", "sa", "root", "user", "guest", "test", "backup", "Administrator", "Admin")
        $isCommon = $user.Key -in $commonUsers
        $rowClass = if ($isCommon) { "common-user" } else { "real-user" }
        $marker = if ($isCommon) { "<span class='badge badge-yellow'>YAYGIN</span>" } else { "<span class='badge badge-red'>DIKKAT</span>" }
        $targetedUsersHtml += @"
        <tr class="$rowClass">
            <td>$rank</td>
            <td><strong>$($user.Key)</strong> $marker</td>
            <td class="text-right">$($user.Value)</td>
        </tr>
"@
        $rank++
    }
    if (-not $targetedUsersHtml) {
        $targetedUsersHtml = "<tr><td colspan='3' class='empty-row'>Hedeflenen kullanici adi yok</td></tr>"
    }
    
    # Alerts
    $alertsHtml = ""
    if ($bruteForceAnalysis.Alerts.Count -gt 0) {
        foreach ($alert in $bruteForceAnalysis.Alerts) {
            $severityClass = switch ($alert.Severity) {
                "CRITICAL" { "alert-critical" }
                "HIGH" { "alert-high" }
                default { "alert-medium" }
            }
            $alertsHtml += @"
            <div class="alert-card $severityClass">
                <div class="alert-header">
                    <span class="alert-type">$($alert.Type)</span>
                    <span class="alert-severity">$($alert.Severity)</span>
                </div>
                <div class="alert-body">
                    <div class="alert-ip">$($alert.IP)</div>
                    <div class="alert-geo">$($alert.Country), $($alert.City)</div>
                    <div class="alert-isp">$($alert.ISP)</div>
                </div>
                <div class="alert-footer">
                    <span><strong>$($alert.AttemptCount)</strong> deneme</span>
                    <span>$($alert.TimeWindow)</span>
                </div>
            </div>
"@
        }
    } else {
        $alertsHtml = "<div class='no-alerts'>Son 24 saatte brute-force saldirisi tespit edilmedi</div>"
    }
    
    # Successful logins
    $successTableHtml = ""
    $successfulLogons | Sort-Object TimeCreated -Descending | Select-Object -First 30 | ForEach-Object {
        $geo = $geoData[$_.SourceIP]
        $geoStr = if ($geo) { "$($geo.Country), $($geo.City)" } else { "Unknown" }
        $ispStr = if ($geo) { $geo.ISP } else { "Unknown" }
        $isLocal = $_.SourceIP -match "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
        $rowClass = if ($isLocal) { "local-row" } else { "" }
        $successTableHtml += @"
        <tr class="$rowClass">
            <td class="mono">$($_.TimeCreated.ToString('dd.MM HH:mm:ss'))</td>
            <td><strong>$($_.Domain)\$($_.Username)</strong></td>
            <td class="mono">$($_.SourceIP)</td>
            <td>$geoStr</td>
            <td class="desktop-only">$ispStr</td>
        </tr>
"@
    }
    if (-not $successTableHtml) {
        $successTableHtml = "<tr><td colspan='5' class='empty-row'>Basarili giris yok</td></tr>"
    }
    
    # Failed logins (detailed)
    $failedTableHtml = ""
    $failedLogons | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object {
        $geo = $geoData[$_.SourceIP]
        $geoStr = if ($geo) { "$($geo.Country), $($geo.City)" } else { "Unknown" }
        $ispStr = if ($geo) { $geo.ISP } else { "Unknown" }
        $failedTableHtml += @"
        <tr>
            <td class="mono">$($_.TimeCreated.ToString('dd.MM HH:mm:ss'))</td>
            <td>$($_.Domain)\$($_.Username)</td>
            <td class="mono">$($_.SourceIP)</td>
            <td>$geoStr</td>
            <td class="desktop-only">$ispStr</td>
        </tr>
"@
    }
    if (-not $failedTableHtml) {
        $failedTableHtml = "<tr><td colspan='5' class='empty-row'>Basarisiz giris yok</td></tr>"
    }
    
    # Active sessions
    $sessionsTableHtml = ""
    foreach ($session in $sessions) {
        $stateClass = switch ($session.State) {
            "Active" { "state-active" }
            "Disc" { "state-disc" }
            default { "" }
        }
        $sessionsTableHtml += @"
        <tr>
            <td><strong>$($session.Username)</strong></td>
            <td>$($session.SessionID)</td>
            <td><span class="$stateClass">$($session.State)</span></td>
            <td>$($session.IdleTime)</td>
            <td>$($session.LogonTime)</td>
        </tr>
"@
    }
    if (-not $sessionsTableHtml) {
        $sessionsTableHtml = "<tr><td colspan='5' class='empty-row'>Aktif oturum yok</td></tr>"
    }
    
    # --- HTML TEMPLATE ---
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RDP Security - Gunluk Rapor - $reportDateStr</title>
    <style>
        :root {
            --bg-body: #0f172a;
            --bg-card: #1e293b;
            --bg-card-alt: #334155;
            --bg-hover: #475569;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dark: #1e293b;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f59e0b;
            --accent-purple: #8b5cf6;
            --border: #334155;
            --gradient-1: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-2: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --gradient-3: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-body);
            color: var(--text-main);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            background: var(--gradient-1);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .header-left h1 {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .header-left h1::before {
            content: '';
            width: 6px;
            height: 35px;
            background: rgba(255,255,255,0.8);
            border-radius: 3px;
        }
        
        .header-left p {
            opacity: 0.9;
            font-size: 0.95rem;
        }
        
        .header-right {
            text-align: right;
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }
        
        .summary-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid var(--border);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }
        
        .summary-card h3 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .summary-card p {
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .summary-card.success h3 { color: var(--accent-green); }
        .summary-card.danger h3 { color: var(--accent-red); }
        .summary-card.warning h3 { color: var(--accent-orange); }
        .summary-card.info h3 { color: var(--accent-blue); }
        .summary-card.purple h3 { color: var(--accent-purple); }
        
        /* Sections */
        .section {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
        }
        
        .section-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid var(--border);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--accent-blue);
            border-radius: 2px;
        }
        
        /* Two Column Layout */
        .two-col {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: rgba(0,0,0,0.3);
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }
        
        tr:hover td {
            background: var(--bg-hover);
        }
        
        .mono {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--accent-blue);
        }
        
        .text-right { text-align: right; }
        .text-danger { color: var(--accent-red); }
        .text-success { color: var(--accent-green); }
        
        .rank-badge {
            background: var(--bg-card-alt);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .danger-row td { background: rgba(239, 68, 68, 0.1); }
        .local-row td { background: rgba(16, 185, 129, 0.1); }
        .common-user td { background: rgba(245, 158, 11, 0.1); }
        .real-user td { background: rgba(239, 68, 68, 0.1); }
        
        .empty-row {
            text-align: center;
            padding: 30px !important;
            color: var(--text-muted);
            font-style: italic;
        }
        
        .badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            margin-left: 8px;
        }
        
        .badge-yellow { background: var(--accent-orange); color: var(--text-dark); }
        .badge-red { background: var(--accent-red); color: white; }
        
        .state-active { color: var(--accent-green); font-weight: 600; }
        .state-disc { color: var(--accent-orange); }
        
        /* Country Bars */
        .country-item {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }
        
        .country-name {
            width: 100px;
            font-size: 0.85rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .country-bar-container {
            flex: 1;
            height: 24px;
            background: var(--bg-card-alt);
            border-radius: 6px;
            overflow: hidden;
        }
        
        .country-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--accent-red), var(--accent-orange));
            border-radius: 6px;
            min-width: 4px;
        }
        
        .country-count {
            width: 50px;
            text-align: right;
            font-weight: 600;
            color: var(--accent-red);
        }
        
        /* Hourly Chart */
        .hourly-chart {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            height: 180px;
            gap: 4px;
            padding: 10px 0;
        }
        
        .hour-bar-wrapper {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            height: 100%;
        }
        
        .hour-value {
            font-size: 0.65rem;
            color: var(--text-muted);
            margin-bottom: 4px;
            min-height: 14px;
        }
        
        .hour-bar {
            width: 100%;
            border-radius: 4px 4px 0 0;
            transition: height 0.3s ease;
        }
        
        .bar-high { background: linear-gradient(180deg, var(--accent-red), #dc2626); }
        .bar-medium { background: linear-gradient(180deg, var(--accent-orange), #d97706); }
        .bar-low { background: linear-gradient(180deg, var(--accent-blue), #2563eb); }
        
        .hour-label {
            font-size: 0.65rem;
            color: var(--text-muted);
            margin-top: 6px;
        }
        
        /* Alerts */
        .alerts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }
        
        .alert-card {
            background: var(--bg-card-alt);
            border-radius: 10px;
            padding: 15px;
            border-left: 4px solid;
        }
        
        .alert-critical { border-color: var(--accent-red); }
        .alert-high { border-color: var(--accent-orange); }
        .alert-medium { border-color: var(--accent-blue); }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .alert-type {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        
        .alert-severity {
            font-size: 0.7rem;
            padding: 2px 8px;
            border-radius: 4px;
            background: var(--accent-red);
            color: white;
        }
        
        .alert-body .alert-ip {
            font-family: monospace;
            font-size: 1.1rem;
            color: var(--accent-blue);
            margin-bottom: 5px;
        }
        
        .alert-body .alert-geo,
        .alert-body .alert-isp {
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        
        .alert-footer {
            display: flex;
            justify-content: space-between;
            margin-top: 12px;
            padding-top: 10px;
            border-top: 1px solid var(--border);
            font-size: 0.85rem;
        }
        
        .alert-footer strong {
            color: var(--accent-red);
        }
        
        .no-alerts {
            text-align: center;
            padding: 40px;
            color: var(--accent-green);
            font-size: 1rem;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 25px;
            color: var(--text-muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            margin-top: 20px;
        }
        
        .footer a {
            color: var(--accent-blue);
            text-decoration: none;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header { flex-direction: column; text-align: center; }
            .header-right { text-align: center; }
            .two-col { grid-template-columns: 1fr; }
            .desktop-only { display: none; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .hourly-chart { overflow-x: auto; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h1>Gunluk Guvenlik Raporu</h1>
                <p>RDP Security Intelligence System v3.0</p>
            </div>
            <div class="header-right">
                <strong>$env:COMPUTERNAME</strong><br>
                $reportDateStr<br>
                $(Get-Date -Format "HH:mm")
            </div>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card success">
                <h3>$successCount</h3>
                <p>Basarili Giris</p>
            </div>
            <div class="summary-card danger">
                <h3>$failedCount</h3>
                <p>Basarisiz Deneme</p>
            </div>
            <div class="summary-card warning">
                <h3>$uniqueAttackerCount</h3>
                <p>Farkli Saldirgan</p>
            </div>
            <div class="summary-card info">
                <h3>$sessionCount</h3>
                <p>Aktif Oturum</p>
            </div>
            <div class="summary-card purple">
                <h3>$alertCount</h3>
                <p>Guvenlik Alarmi</p>
            </div>
        </div>
        
        <!-- Alerts Section -->
        <div class="section">
            <div class="section-title">Guvenlik Alarmlari</div>
            <div class="alerts-grid">
                $alertsHtml
            </div>
        </div>
        
        <!-- Top Attackers -->
        <div class="section">
            <div class="section-title">En Cok Saldiran IP Adresleri (Top 15)</div>
            <table>
                <thead>
                    <tr>
                        <th width="50">#</th>
                        <th>IP Adresi</th>
                        <th>Ulke</th>
                        <th class="desktop-only">Sehir</th>
                        <th class="desktop-only">ISP</th>
                        <th class="text-right">Deneme</th>
                    </tr>
                </thead>
                <tbody>
                    $topAttackersHtml
                </tbody>
            </table>
        </div>
        
        <!-- Two Column: Country & Hourly -->
        <div class="two-col">
            <div class="section">
                <div class="section-title">Ulke Dagilimi</div>
                $countryBarsHtml
            </div>
            <div class="section">
                <div class="section-title">Saatlik Saldiri Yogunlugu (24 Saat)</div>
                <div class="hourly-chart">
                    $hourlyChartHtml
                </div>
            </div>
        </div>
        
        <!-- Two Column: Targeted Users & Active Sessions -->
        <div class="two-col">
            <div class="section">
                <div class="section-title">Hedeflenen Kullanici Adlari</div>
                <table>
                    <thead>
                        <tr>
                            <th width="40">#</th>
                            <th>Kullanici Adi</th>
                            <th class="text-right">Deneme</th>
                        </tr>
                    </thead>
                    <tbody>
                        $targetedUsersHtml
                    </tbody>
                </table>
            </div>
            <div class="section">
                <div class="section-title">Aktif Oturumlar</div>
                <table>
                    <thead>
                        <tr>
                            <th>Kullanici</th>
                            <th>Session</th>
                            <th>Durum</th>
                            <th>Bosta</th>
                            <th>Giris</th>
                        </tr>
                    </thead>
                    <tbody>
                        $sessionsTableHtml
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Successful Logins -->
        <div class="section">
            <div class="section-title">Basarili Girisler (Son 30)</div>
            <table>
                <thead>
                    <tr>
                        <th>Zaman</th>
                        <th>Kullanici</th>
                        <th>IP Adresi</th>
                        <th>Konum</th>
                        <th class="desktop-only">ISP</th>
                    </tr>
                </thead>
                <tbody>
                    $successTableHtml
                </tbody>
            </table>
        </div>
        
        <!-- Failed Logins -->
        <div class="section">
            <div class="section-title">Basarisiz Denemeler (Son 50)</div>
            <table>
                <thead>
                    <tr>
                        <th>Zaman</th>
                        <th>Kullanici</th>
                        <th>IP Adresi</th>
                        <th>Konum</th>
                        <th class="desktop-only">ISP</th>
                    </tr>
                </thead>
                <tbody>
                    $failedTableHtml
                </tbody>
            </table>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            RDP Security Intelligence System v3.0 | 
            Olusturulma: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |
            <a href="https://github.com/furkandncer">GitHub</a>
        </div>
    </div>
</body>
</html>
"@
    
    # UTF-8 BOM olmadan kaydet
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($reportPath, $html, $utf8NoBom)
        Write-Host "[+] Gunluk rapor olusturuldu: $reportPath" -ForegroundColor Green
    }
    catch {
        $html | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "[+] Gunluk rapor olusturuldu: $reportPath" -ForegroundColor Green
    }
    
    Write-SecurityLog -LogType "Alert" -Message "Daily report generated" -Severity "INFO" -Data @{Path = $reportPath}
    return $reportPath
}


function New-WeeklyReport {
    param([DateTime]$TargetDate = (Get-Date))
    
    $reportDateStr = $TargetDate.ToString("yyyy-MM-dd")
    $weekStart = $TargetDate.AddDays(-7)
    $reportPath = Join-Path $Config.ReportPath "weekly_report_$reportDateStr.html"
    
    Write-Host "[*] Haftalik rapor hazirlaniyor..." -ForegroundColor Cyan
    Write-Host "  - Tarih araligi: $($weekStart.ToString('dd.MM.yyyy')) - $($TargetDate.ToString('dd.MM.yyyy'))" -ForegroundColor Gray
    
    # --- EVENT LOG'DAN VERI CEKME (OPTIMIZE) ---
    Write-Host "  - Event Log okunuyor..." -ForegroundColor Gray
    
    $allSuccessful = @()
    $allFailed = @()
    
    # Basarili RDP girisleri
    try {
        Write-Host "    - Basarili girisler okunuyor..." -ForegroundColor DarkGray
        $allSuccessful = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4624
            StartTime = $weekStart
        } -MaxEvents 5000 -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties[8].Value -eq 10
        })
        Write-Host "    - Basarili RDP giris: $($allSuccessful.Count)" -ForegroundColor Green
    } catch {
        Write-Host "    - Basarili giris: 0 (log bos veya hata)" -ForegroundColor Yellow
        $allSuccessful = @()
    }
    
    # Basarisiz girisler - LIMITLI cek (cok fazla olabilir)
    try {
        Write-Host "    - Basarisiz girisler okunuyor (max 50000)..." -ForegroundColor DarkGray
        $allFailed = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4625
            StartTime = $weekStart
        } -MaxEvents 50000 -ErrorAction SilentlyContinue)
        Write-Host "    - Basarisiz giris: $($allFailed.Count)" -ForegroundColor Red
    } catch {
        Write-Host "    - Basarisiz giris: 0 (log bos veya hata)" -ForegroundColor Yellow
        $allFailed = @()
    }
    
    # --- GUNLUK ISTATISTIKLER ---
    Write-Host "  - Gunluk istatistikler hesaplaniyor..." -ForegroundColor Gray
    
    $dailyStats = @{}
    $dayNames = @{ "Monday"="Pzt"; "Tuesday"="Sal"; "Wednesday"="Car"; "Thursday"="Per"; "Friday"="Cum"; "Saturday"="Cmt"; "Sunday"="Paz" }
    
    for ($i = 6; $i -ge 0; $i--) {
        $d = $TargetDate.AddDays(-$i)
        $dateStr = $d.ToString("yyyy-MM-dd")
        $dayLabel = $dayNames[$d.DayOfWeek.ToString()]
        $dailyStats[$dateStr] = @{ 
            Success = 0
            Failed = 0
            Label = $dayLabel
            Date = $dateStr
            ShortDate = $d.ToString("dd.MM")
        }
    }
    
    # Basarili girisleri gunlere dagit
    foreach ($event in $allSuccessful) {
        $dateKey = $event.TimeCreated.ToString("yyyy-MM-dd")
        if ($dailyStats.ContainsKey($dateKey)) {
            $dailyStats[$dateKey].Success++
        }
    }
    
    # Basarisiz girisleri gunlere dagit
    foreach ($event in $allFailed) {
        $dateKey = $event.TimeCreated.ToString("yyyy-MM-dd")
        if ($dailyStats.ContainsKey($dateKey)) {
            $dailyStats[$dateKey].Failed++
        }
    }
    
    # --- IP VE GEOIP ANALIZI ---
    Write-Host "  - IP analizi ve GeoIP sorgulari..." -ForegroundColor Gray
    
    $ipStats = @{}
    $userStats = @{}
    $hourlyStats = @{}
    for ($h = 0; $h -lt 24; $h++) { $hourlyStats[$h] = 0 }
    
    foreach ($event in $allFailed) {
        $sourceIP = $event.Properties[19].Value
        $username = $event.Properties[5].Value
        $hour = $event.TimeCreated.Hour
        
        # Saatlik dagilim
        $hourlyStats[$hour]++
        
        # IP istatistikleri
        if ($sourceIP -and $sourceIP -ne "-") {
            if (-not $ipStats.ContainsKey($sourceIP)) {
                $ipStats[$sourceIP] = @{ Count = 0; FirstSeen = $event.TimeCreated; LastSeen = $event.TimeCreated }
            }
            $ipStats[$sourceIP].Count++
            if ($event.TimeCreated -lt $ipStats[$sourceIP].FirstSeen) { $ipStats[$sourceIP].FirstSeen = $event.TimeCreated }
            if ($event.TimeCreated -gt $ipStats[$sourceIP].LastSeen) { $ipStats[$sourceIP].LastSeen = $event.TimeCreated }
        }
        
        # Kullanici istatistikleri
        if ($username) {
            if (-not $userStats.ContainsKey($username)) { $userStats[$username] = 0 }
            $userStats[$username]++
        }
    }
    
    # Top 20 IP icin GeoIP sorgula
    $topIPsForGeo = $ipStats.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 20
    $geoCache = @{}
    $geoCount = 0
    foreach ($ipEntry in $topIPsForGeo) {
        $geoCount++
        Write-Host "    - GeoIP $geoCount/20: $($ipEntry.Key)..." -ForegroundColor DarkGray
        $geo = Get-GeoIPInfo -IPAddress $ipEntry.Key
        $geoCache[$ipEntry.Key] = $geo
        $ipStats[$ipEntry.Key].Country = $geo.Country
        $ipStats[$ipEntry.Key].City = $geo.City
        $ipStats[$ipEntry.Key].ISP = $geo.ISP
        $ipStats[$ipEntry.Key].CountryCode = $geo.CountryCode
    }
    
    # --- HESAPLAMALAR ---
    $totalSuccess = 0
    $totalFailed = 0
    foreach ($day in $dailyStats.Keys) {
        $totalSuccess += $dailyStats[$day].Success
        $totalFailed += $dailyStats[$day].Failed
    }
    
    $uniqueAttackerCount = $ipStats.Count
    $topAttackers = $ipStats.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 15
    $topUsers = $userStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15
    
    # Ulke dagilimi
    $countryStats = @{}
    foreach ($ipEntry in $topIPsForGeo) {
        $country = $ipStats[$ipEntry.Key].Country
        if ($country -and $country -ne "Unknown" -and $country -ne "Local/Private") {
            if (-not $countryStats.ContainsKey($country)) { $countryStats[$country] = 0 }
            $countryStats[$country] += $ipStats[$ipEntry.Key].Count
        }
    }
    $topCountries = $countryStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    $totalCountryAttempts = ($topCountries | Measure-Object -Property Value -Sum).Sum
    if (-not $totalCountryAttempts -or $totalCountryAttempts -eq 0) { $totalCountryAttempts = 1 }
    
    # En yogun saat
    $peakHour = ($hourlyStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
    $peakHourCount = $hourlyStats[$peakHour]
    $maxHourly = ($hourlyStats.Values | Measure-Object -Maximum).Maximum
    if (-not $maxHourly -or $maxHourly -eq 0) { $maxHourly = 1 }
    
    # En aktif gun
    $peakDay = ($dailyStats.GetEnumerator() | Sort-Object { $_.Value.Failed } -Descending | Select-Object -First 1)
    
    Write-Host "  - HTML olusturuluyor..." -ForegroundColor Gray
    
    # --- HTML ELEMANLARI ---
    
    # Gunluk trend chart
    $maxDailyVal = ($dailyStats.Values | ForEach-Object { $_.Success + $_.Failed } | Measure-Object -Maximum).Maximum
    if (-not $maxDailyVal -or $maxDailyVal -eq 0) { $maxDailyVal = 1 }
    
    $dailyChartHtml = ""
    foreach ($stat in ($dailyStats.Values | Sort-Object Date)) {
        $total = $stat.Success + $stat.Failed
        $failedHeight = if ($stat.Failed -gt 0) { [math]::Round(($stat.Failed / $maxDailyVal) * 100) } else { 0 }
        $successHeight = if ($stat.Success -gt 0) { [math]::Round(($stat.Success / $maxDailyVal) * 100) } else { 0 }
        
        $dailyChartHtml += @"
        <div class="day-column">
            <div class="day-values">
                <span class="failed-val">$($stat.Failed)</span>
                <span class="success-val">$($stat.Success)</span>
            </div>
            <div class="stacked-bar">
                <div class="bar-failed" style="height: $(if($failedHeight -lt 2 -and $stat.Failed -gt 0){2}else{$failedHeight})%"></div>
                <div class="bar-success" style="height: $(if($successHeight -lt 2 -and $stat.Success -gt 0){2}else{$successHeight})%"></div>
            </div>
            <div class="day-label">$($stat.Label)</div>
            <div class="day-date">$($stat.ShortDate)</div>
        </div>
"@
    }
    
    # Saatlik chart
    $hourlyChartHtml = ""
    for ($h = 0; $h -lt 24; $h++) {
        $count = $hourlyStats[$h]
        $height = if ($count -gt 0) { [math]::Round(($count / $maxHourly) * 100) } else { 0 }
        $barClass = if ($h -eq $peakHour) { "bar-peak" } elseif ($count -gt ($maxHourly * 0.5)) { "bar-high" } elseif ($count -gt 0) { "bar-normal" } else { "bar-zero" }
        $hourlyChartHtml += @"
        <div class="hour-col">
            <div class="hour-val">$(if($count -gt 0){$count}else{''})</div>
            <div class="hour-bar $barClass" style="height: $(if($height -lt 2 -and $count -gt 0){2}else{$height})%"></div>
            <div class="hour-lbl">$('{0:D2}' -f $h)</div>
        </div>
"@
    }
    
    # Top attackers table
    $topAttackersHtml = ""
    $rank = 1
    foreach ($attacker in $topAttackers) {
        $geo = if ($geoCache.ContainsKey($attacker.Key)) { $geoCache[$attacker.Key] } else { @{Country="?";City="?";ISP="?"} }
        $countryDisplay = if ($attacker.Value.Country) { $attacker.Value.Country } else { $geo.Country }
        $cityDisplay = if ($attacker.Value.City) { $attacker.Value.City } else { $geo.City }
        $ispDisplay = if ($attacker.Value.ISP) { $attacker.Value.ISP } else { $geo.ISP }
        $dangerCountries = @("CN", "RU", "KP", "IR", "BD", "VN", "IN", "PK", "BR")
        $countryCode = if ($attacker.Value.CountryCode) { $attacker.Value.CountryCode } else { "??" }
        $rowClass = if ($countryCode -in $dangerCountries) { "danger-row" } else { "" }
        $duration = if ($attacker.Value.FirstSeen -and $attacker.Value.LastSeen) {
            $span = $attacker.Value.LastSeen - $attacker.Value.FirstSeen
            if ($span.TotalDays -ge 1) { "$([math]::Round($span.TotalDays,1)) gun" }
            elseif ($span.TotalHours -ge 1) { "$([math]::Round($span.TotalHours,1)) saat" }
            else { "$([math]::Round($span.TotalMinutes,0)) dk" }
        } else { "-" }
        
        $topAttackersHtml += @"
        <tr class="$rowClass">
            <td><span class="rank-badge">$rank</span></td>
            <td class="mono">$($attacker.Key)</td>
            <td>$countryDisplay</td>
            <td class="desktop-only">$cityDisplay</td>
            <td class="desktop-only">$ispDisplay</td>
            <td class="desktop-only">$duration</td>
            <td class="text-right text-danger"><strong>$($attacker.Value.Count)</strong></td>
        </tr>
"@
        $rank++
    }
    if (-not $topAttackersHtml) {
        $topAttackersHtml = "<tr><td colspan='7' class='empty-row'>Bu hafta saldiri tespit edilmedi</td></tr>"
    }
    
    # Top targeted users
    $topUsersHtml = ""
    $rank = 1
    $commonUsers = @("administrator", "admin", "sa", "root", "user", "guest", "test", "backup", "Administrator", "Admin", "ADMIN", "ROOT", "USER")
    foreach ($user in $topUsers) {
        $isCommon = $user.Key -in $commonUsers -or $user.Key -match "^(admin|user|test|guest)"
        $rowClass = if ($isCommon) { "common-user" } else { "real-user" }
        $badge = if ($isCommon) { "<span class='badge badge-yellow'>YAYGIN</span>" } else { "<span class='badge badge-red'>HEDEF</span>" }
        $topUsersHtml += @"
        <tr class="$rowClass">
            <td>$rank</td>
            <td><strong>$($user.Key)</strong> $badge</td>
            <td class="text-right text-danger">$($user.Value)</td>
        </tr>
"@
        $rank++
    }
    if (-not $topUsersHtml) {
        $topUsersHtml = "<tr><td colspan='3' class='empty-row'>Hedeflenen kullanici adi yok</td></tr>"
    }
    
    # Country bars
    $countryBarsHtml = ""
    foreach ($country in $topCountries) {
        $percent = [math]::Round(($country.Value / $totalCountryAttempts) * 100)
        $countryBarsHtml += @"
        <div class="country-row">
            <div class="country-name">$($country.Key)</div>
            <div class="country-bar-bg">
                <div class="country-bar-fill" style="width: $percent%"></div>
            </div>
            <div class="country-stats">
                <span class="country-count">$($country.Value)</span>
                <span class="country-pct">$percent%</span>
            </div>
        </div>
"@
    }
    if (-not $countryBarsHtml) {
        $countryBarsHtml = "<div class='empty-row'>Ulke verisi yok</div>"
    }
    
    # --- HTML TEMPLATE ---
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Haftalik Guvenlik Raporu - $reportDateStr</title>
    <style>
        :root {
            --bg-body: #0a0f1a;
            --bg-card: #131b2e;
            --bg-card-alt: #1a2744;
            --bg-hover: #243656;
            --text-main: #e8edf5;
            --text-muted: #8892a6;
            --text-dark: #0a0f1a;
            --accent-blue: #4f8cff;
            --accent-green: #00d68f;
            --accent-red: #ff4757;
            --accent-orange: #ffa502;
            --accent-purple: #a855f7;
            --accent-cyan: #00d9ff;
            --border: #2a3a5a;
            --gradient-header: linear-gradient(135deg, #1e3a8a 0%, #7c3aed 50%, #db2777 100%);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-body); color: var(--text-main); line-height: 1.6; }
        .container { max-width: 1500px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            background: var(--gradient-header);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.3;
        }
        .header-content { position: relative; z-index: 1; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px; }
        .header h1 { font-size: 2.2rem; font-weight: 800; margin-bottom: 8px; text-shadow: 0 2px 10px rgba(0,0,0,0.3); }
        .header p { opacity: 0.9; font-size: 1.1rem; }
        .header-right { text-align: right; }
        .header-right .server-name { font-size: 1.3rem; font-weight: 700; }
        .header-right .date-range { opacity: 0.85; margin-top: 5px; }
        
        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 25px;
            border: 1px solid var(--border);
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .summary-card:hover { transform: translateY(-5px); box-shadow: 0 15px 40px rgba(0,0,0,0.4); }
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            border-radius: 16px 16px 0 0;
        }
        .summary-card.green::before { background: var(--accent-green); }
        .summary-card.red::before { background: var(--accent-red); }
        .summary-card.orange::before { background: var(--accent-orange); }
        .summary-card.blue::before { background: var(--accent-blue); }
        .summary-card.purple::before { background: var(--accent-purple); }
        .summary-card.cyan::before { background: var(--accent-cyan); }
        .summary-card h3 { font-size: 2.8rem; font-weight: 800; margin-bottom: 5px; }
        .summary-card.green h3 { color: var(--accent-green); }
        .summary-card.red h3 { color: var(--accent-red); }
        .summary-card.orange h3 { color: var(--accent-orange); }
        .summary-card.blue h3 { color: var(--accent-blue); }
        .summary-card.purple h3 { color: var(--accent-purple); }
        .summary-card.cyan h3 { color: var(--accent-cyan); }
        .summary-card p { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }
        .summary-card .subtext { font-size: 0.75rem; color: var(--text-muted); margin-top: 8px; }
        
        /* Sections */
        .section {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
        }
        .section-title {
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .section-title::before {
            content: '';
            width: 5px;
            height: 24px;
            background: var(--accent-purple);
            border-radius: 3px;
        }
        
        /* Daily Trend Chart */
        .daily-trend {
            display: flex;
            justify-content: space-around;
            align-items: flex-end;
            height: 280px;
            padding: 20px 0;
            gap: 10px;
        }
        .day-column {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            max-width: 120px;
        }
        .day-values {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 10px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .failed-val { color: var(--accent-red); }
        .success-val { color: var(--accent-green); }
        .stacked-bar {
            width: 100%;
            height: 180px;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
            gap: 2px;
        }
        .bar-failed {
            width: 100%;
            background: linear-gradient(180deg, var(--accent-red), #c0392b);
            border-radius: 6px 6px 0 0;
            min-height: 0;
        }
        .bar-success {
            width: 100%;
            background: linear-gradient(180deg, var(--accent-green), #00a86b);
            border-radius: 0 0 6px 6px;
            min-height: 0;
        }
        .day-label { margin-top: 12px; font-weight: 700; font-size: 1rem; }
        .day-date { font-size: 0.75rem; color: var(--text-muted); }
        
        /* Hourly Chart */
        .hourly-chart {
            display: flex;
            align-items: flex-end;
            height: 160px;
            gap: 3px;
            padding: 10px 0;
        }
        .hour-col { flex: 1; display: flex; flex-direction: column; align-items: center; }
        .hour-val { font-size: 0.6rem; color: var(--text-muted); margin-bottom: 4px; min-height: 12px; }
        .hour-bar { width: 100%; border-radius: 3px 3px 0 0; min-height: 2px; }
        .bar-peak { background: var(--accent-red); }
        .bar-high { background: var(--accent-orange); }
        .bar-normal { background: var(--accent-blue); }
        .bar-zero { background: var(--bg-card-alt); min-height: 2px; }
        .hour-lbl { font-size: 0.6rem; color: var(--text-muted); margin-top: 6px; }
        
        /* Tables */
        .two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 25px; margin-bottom: 25px; }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: rgba(0,0,0,0.4);
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 15px 12px;
            text-align: left;
            font-weight: 700;
        }
        td { padding: 14px 12px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        tr:hover td { background: var(--bg-hover); }
        .mono { font-family: 'Consolas', monospace; color: var(--accent-cyan); }
        .text-right { text-align: right; }
        .text-danger { color: var(--accent-red); }
        .rank-badge { background: var(--bg-card-alt); padding: 5px 12px; border-radius: 8px; font-size: 0.85rem; font-weight: 700; }
        .danger-row td { background: rgba(255, 71, 87, 0.1); }
        .common-user td { background: rgba(255, 165, 2, 0.1); }
        .real-user td { background: rgba(255, 71, 87, 0.15); }
        .empty-row { text-align: center; padding: 40px !important; color: var(--text-muted); font-style: italic; }
        .badge { padding: 3px 10px; border-radius: 6px; font-size: 0.7rem; font-weight: 700; margin-left: 10px; }
        .badge-yellow { background: var(--accent-orange); color: var(--text-dark); }
        .badge-red { background: var(--accent-red); color: white; }
        
        /* Country Bars */
        .country-row { display: flex; align-items: center; gap: 15px; margin-bottom: 16px; }
        .country-name { width: 120px; font-size: 0.9rem; font-weight: 600; }
        .country-bar-bg { flex: 1; height: 28px; background: var(--bg-card-alt); border-radius: 8px; overflow: hidden; }
        .country-bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent-red), var(--accent-orange)); border-radius: 8px; }
        .country-stats { display: flex; gap: 10px; width: 100px; justify-content: flex-end; }
        .country-count { font-weight: 700; color: var(--accent-red); }
        .country-pct { color: var(--text-muted); font-size: 0.85rem; }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
            margin-top: 30px;
        }
        .footer a { color: var(--accent-blue); text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
        
        @media (max-width: 768px) {
            .header { padding: 25px; }
            .header h1 { font-size: 1.5rem; }
            .header-content { flex-direction: column; text-align: center; }
            .header-right { text-align: center; }
            .two-col { grid-template-columns: 1fr; }
            .desktop-only { display: none; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .daily-trend { height: 200px; }
            .stacked-bar { height: 120px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div>
                    <h1>Haftalik Guvenlik Raporu</h1>
                    <p>RDP Security Intelligence System v3.0</p>
                </div>
                <div class="header-right">
                    <div class="server-name">$env:COMPUTERNAME</div>
                    <div class="date-range">$($weekStart.ToString('dd.MM.yyyy')) - $($TargetDate.ToString('dd.MM.yyyy'))</div>
                </div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card green">
                <h3>$totalSuccess</h3>
                <p>Basarili Giris</p>
                <div class="subtext">7 gunluk toplam</div>
            </div>
            <div class="summary-card red">
                <h3>$totalFailed</h3>
                <p>Basarisiz Deneme</p>
                <div class="subtext">Engellenen saldiri</div>
            </div>
            <div class="summary-card orange">
                <h3>$uniqueAttackerCount</h3>
                <p>Farkli IP</p>
                <div class="subtext">Benzersiz saldirgan</div>
            </div>
            <div class="summary-card blue">
                <h3>$($peakHour):00</h3>
                <p>En Yogun Saat</p>
                <div class="subtext">$peakHourCount saldiri</div>
            </div>
            <div class="summary-card purple">
                <h3>$($peakDay.Value.Label)</h3>
                <p>En Aktif Gun</p>
                <div class="subtext">$($peakDay.Value.Failed) saldiri</div>
            </div>
            <div class="summary-card cyan">
                <h3>$($topCountries.Count)</h3>
                <p>Farkli Ulke</p>
                <div class="subtext">Saldiri kaynagi</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">7 Gunluk Aktivite Trendi</div>
            <div class="daily-trend">
                $dailyChartHtml
            </div>
            <div style="display: flex; justify-content: center; gap: 30px; margin-top: 15px; font-size: 0.85rem;">
                <span><span style="color: var(--accent-red);">■</span> Basarisiz Giris</span>
                <span><span style="color: var(--accent-green);">■</span> Basarili Giris</span>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Saatlik Saldiri Dagilimi (24 Saat Ortalama)</div>
            <div class="hourly-chart">
                $hourlyChartHtml
            </div>
            <div style="text-align: center; margin-top: 10px; font-size: 0.8rem; color: var(--text-muted);">
                En yogun saat: <strong style="color: var(--accent-red);">$($peakHour):00</strong> ($peakHourCount saldiri)
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">En Cok Saldiran IP Adresleri (Top 15)</div>
            <table>
                <thead>
                    <tr>
                        <th width="50">#</th>
                        <th>IP Adresi</th>
                        <th>Ulke</th>
                        <th class="desktop-only">Sehir</th>
                        <th class="desktop-only">ISP</th>
                        <th class="desktop-only">Sure</th>
                        <th class="text-right">Deneme</th>
                    </tr>
                </thead>
                <tbody>
                    $topAttackersHtml
                </tbody>
            </table>
        </div>
        
        <div class="two-col">
            <div class="section">
                <div class="section-title">Saldiri Kaynak Ulkeleri</div>
                $countryBarsHtml
            </div>
            <div class="section">
                <div class="section-title">Hedeflenen Kullanici Adlari (Top 15)</div>
                <table>
                    <thead>
                        <tr>
                            <th width="40">#</th>
                            <th>Kullanici Adi</th>
                            <th class="text-right">Deneme</th>
                        </tr>
                    </thead>
                    <tbody>
                        $topUsersHtml
                    </tbody>
                </table>
                <div style="margin-top: 15px; font-size: 0.8rem; color: var(--text-muted);">
                    <span style="background: rgba(255,165,2,0.2); padding: 2px 8px; border-radius: 4px;">YAYGIN</span> = Bilinen default kullanici adi
                    <span style="background: rgba(255,71,87,0.2); padding: 2px 8px; border-radius: 4px; margin-left: 10px;">HEDEF</span> = Gercek hesap olabilir
                </div>
            </div>
        </div>
        
        <div class="footer">
            RDP Security Intelligence System v3.0 |
            Rapor: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |
            <a href="https://github.com/furkandncer">GitHub</a>
        </div>
    </div>
</body>
</html>
"@
    
    # --- DOSYA KAYDET ---
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($reportPath, $html, $utf8NoBom)
        Write-Host "[+] Haftalik rapor olusturuldu: $reportPath" -ForegroundColor Green
    }
    catch {
        $html | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "[+] Haftalik rapor olusturuldu: $reportPath" -ForegroundColor Green
    }
    
    Write-SecurityLog -LogType "Alert" -Message "Weekly report generated" -Severity "INFO" -Data @{Path = $reportPath}
    return $reportPath
}


function Start-RDPMonitoringService {
    param([switch]$Verbose)
    
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "       RDP Security Intelligence Monitoring System" -ForegroundColor Yellow
    Write-Host "                  v3.0 by Furkan Dincer" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "[+] Connection Monitoring    [+] GeoIP Intelligence" -ForegroundColor Green
    Write-Host "[+] Session Tracking         [+] Brute Force Detection" -ForegroundColor Green
    Write-Host "[+] Process Activity         [+] Real-time Alerting" -ForegroundColor Green
    Write-Host "[+] Auto IP Blocking         [+] Whitelist Support" -ForegroundColor Green
    Write-Host "[+] Rate Limiting            [+] Suspicious Process" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    
    Initialize-LogDirectories
    $lastEventTime = Get-Date
    $lastCleanupCheck = Get-Date
    
    while ($true) {
        try {
            # Suresi dolmus engellemeleri kaldir (her saat)
            if (((Get-Date) - $lastCleanupCheck).TotalHours -ge 1) {
                Clear-ExpiredBlocks
                $lastCleanupCheck = Get-Date
            }
            
            $newEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                ID        = @(4624, 4625)
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue | Where-Object {
                ($_.Properties[8].Value -eq 10) -or ($_.Properties[10].Value -in @(3, 10))
            }
            
            foreach ($event in $newEvents) {
                $isSuccess = $event.Id -eq 4624
                $sourceIP = if ($isSuccess) { $event.Properties[18].Value } else { $event.Properties[19].Value }
                $username = $event.Properties[5].Value
                $domain = $event.Properties[6].Value
                
                $geoInfo = Get-GeoIPInfo -IPAddress $sourceIP
                
                # Whitelist kontrolu
                $isWhitelisted = Test-WhitelistedIP -IPAddress $sourceIP
                
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
                    Whitelisted  = $isWhitelisted
                }
                
                $severity = if ($isSuccess) { "INFO" } else { "WARNING" }
                $message = if ($isSuccess) { 
                    "RDP login: $domain\$username from $sourceIP ($($geoInfo.Country), $($geoInfo.City))"
                } else {
                    "Failed RDP: $domain\$username from $sourceIP ($($geoInfo.Country), $($geoInfo.City))"
                }
                
                Write-SecurityLog -LogType "Connection" -Message $message -Severity $severity -Data $eventData
                
                # Whitelist'te degilse alert gonder
                if (-not $isWhitelisted) {
                    if ($isSuccess) {
                        Send-Alert -Title "RDP Giris Yapildi" -Message "$domain\$username baglandi" -Data @{
                            Kullanici = "$domain\$username"
                            IP = $sourceIP
                            Ulke = $geoInfo.Country
                            Sehir = $geoInfo.City
                            ISP = $geoInfo.ISP
                            Zaman = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        } -Severity "INFO"
                        
                        # Basarili giristen sonra supheli process kontrolu
                        $suspiciousProcs = Watch-UserProcesses -Username $username
                    } else {
                        Send-Alert -Title "Basarisiz RDP Denemesi" -Message "$domain\$username giris yapamadi" -Data @{
                            Kullanici = "$domain\$username"
                            IP = $sourceIP
                            Ulke = $geoInfo.Country
                            Sehir = $geoInfo.City
                            ISP = $geoInfo.ISP
                            Zaman = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        } -Severity "WARNING"
                        
                        # Rate limit kontrolu
                        if (Test-RateLimit -IPAddress $sourceIP) {
                            Send-Alert -Title "RATE LIMIT ASILDI" -Message "$sourceIP cok fazla deneme yapiyor!" -Data @{
                                IP = $sourceIP
                                Ulke = $geoInfo.Country
                                Limit = "$($Config.RateLimitPerMinute)/dakika"
                            } -Severity "CRITICAL"
                        }
                    }
                    
                    # Supheli ulke kontrolu
                    if ($geoInfo.CountryCode -in $Config.SuspiciousCountries) {
                        Send-Alert -Title "SUPHELI ULKE UYARISI" -Message "Tehlikeli bolgeden baglanti denemesi!" -Data $eventData -Severity "CRITICAL"
                    }
                }
            }
            
            if ($newEvents) {
                $lastEventTime = ($newEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.AddSeconds(1)
            }
            
            # Her 5 dakikada bir brute force analizi ve otomatik engelleme
            if ((Get-Date).Minute % 5 -eq 0 -and (Get-Date).Second -lt 10) {
                $bruteForce = Get-FailedLoginAnalysis -TimeWindowMinutes $([math]::Ceiling($Config.FailedLoginTimeWindow / 60)) -Threshold $Config.FailedLoginThreshold
                
                foreach ($alert in $bruteForce.Alerts) {
                    # Whitelist kontrolu
                    if (-not (Test-WhitelistedIP -IPAddress $alert.IP)) {
                        Send-Alert -Title "Brute Force Saldirisi Tespit Edildi" -Message "Coklu basarisiz giris: $($alert.IP)" -Data $alert -Severity $alert.Severity
                        
                        # Otomatik engelleme
                        if ($Config.EnableAutoBlock -and $alert.AttemptCount -ge $Config.AutoBlockThreshold) {
                            Block-IPAddress -IPAddress $alert.IP -Reason "Brute-force: $($alert.AttemptCount) attempts" -DurationDays $Config.AutoBlockDurationDays
                        }
                    }
                }
            }
            
            # Her 5 dakikada session ve supheli process kontrolu
            if ((Get-Date).Minute % 5 -eq 0 -and (Get-Date).Second -lt 10) {
                $sessions = Get-ActiveRDPSessions
                foreach ($session in $sessions) {
                    $processes = Get-UserProcesses -Username $session.Username
                    
                    # Supheli process kontrolu
                    foreach ($proc in $processes) {
                        if (Test-SuspiciousProcess -ProcessName $proc.ProcessName) {
                            Send-Alert -Title "SUPHELI PROCESS" -Message "$($session.Username) supheli process calistiriyor: $($proc.ProcessName)" -Data @{
                                Kullanici = $session.Username
                                Process = $proc.ProcessName
                                PID = $proc.ProcessID
                                Yol = $proc.Path
                            } -Severity "CRITICAL"
                        }
                    }
                    
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
    
    $weeklyAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& {. '$scriptDestination'; New-WeeklyReport}`""
    $weeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "00:05"
    Register-ScheduledTask -TaskName "RDP Security Weekly Report" -Action $weeklyAction -Trigger $weeklyTrigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "[+] Weekly Report kuruldu (Pazartesi 00:05)" -ForegroundColor Green
    
    $cleanupAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Get-ChildItem -Path 'C:\RDP-Security-Logs' -Recurse -File | Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-$($Config.LogRetentionDays)) } | Remove-Item -Force; & {. '$scriptDestination'; Clear-ExpiredBlocks}`""
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
    Write-Host "[+] Her gun 23:55'te gunluk rapor" -ForegroundColor Green
    Write-Host "[+] Her Pazartesi 00:05'te haftalik rapor" -ForegroundColor Green
    Write-Host "[+] Otomatik IP engelleme aktif" -ForegroundColor Green
    Write-Host "[+] 90 gunden eski loglar silinir" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "WHITELIST AYARI:" -ForegroundColor Yellow
    Write-Host "  Kendi IP'lerinizi whitelist'e ekleyin:" -ForegroundColor Gray
    Write-Host "  Add-WhitelistIP -IPAddress 'YOUR_IP'" -ForegroundColor Gray
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
    
    $tasks = @("RDP Security Monitoring Service", "RDP Security Daily Report", "RDP Security Weekly Report", "RDP Security Log Cleanup")
    
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
    Write-Host "       RDP Security Intelligence System v3.0" -ForegroundColor Yellow
    Write-Host "                  by Furkan Dincer" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "KURULUM:" -ForegroundColor White
    Write-Host "  . .\RDP-Security-Intelligence.ps1     # Script'i yukle" -ForegroundColor Gray
    Write-Host "  Test-TelegramConnection           # Telegram test" -ForegroundColor Gray
    Write-Host "  Install-MonitoringScheduledTasks  # Servisi kur" -ForegroundColor Gray
    Write-Host ""
    Write-Host "DURUM:" -ForegroundColor White
    Write-Host "  Get-MonitoringServiceStatus       # Servis durumu" -ForegroundColor Gray
    Write-Host "  Get-QuickSecurityStatus           # Hizli ozet" -ForegroundColor Gray
    Write-Host "  Get-RDPConnections                # Son 24 saat" -ForegroundColor Gray
    Write-Host ""
    Write-Host "RAPORLAR:" -ForegroundColor White
    Write-Host "  New-DailyReport                   # Gunluk HTML rapor" -ForegroundColor Gray
    Write-Host "  New-WeeklyReport                  # Haftalik HTML rapor" -ForegroundColor Gray
    Write-Host "  Show-TargetedUsernames            # Hedeflenen kullanici adlari" -ForegroundColor Gray
    Write-Host ""
    Write-Host "WHITELIST:" -ForegroundColor White
    Write-Host "  Get-WhitelistIPs                  # Whitelist goster" -ForegroundColor Gray
    Write-Host "  Add-WhitelistIP -IP '1.2.3.4'     # Whitelist'e ekle" -ForegroundColor Gray
    Write-Host "  Remove-WhitelistIP -IP '1.2.3.4'  # Whitelist'ten cikar" -ForegroundColor Gray
    Write-Host ""
    Write-Host "IP ENGELLEME:" -ForegroundColor White
    Write-Host "  Get-BlockedIPs                    # Engellenen IP'ler" -ForegroundColor Gray
    Write-Host "  Block-IPAddress -IP '1.2.3.4'     # IP engelle" -ForegroundColor Gray
    Write-Host "  Unblock-IPAddress -IP '1.2.3.4'   # Engeli kaldir" -ForegroundColor Gray
    Write-Host "  Clear-ExpiredBlocks               # Suresi dolanlari temizle" -ForegroundColor Gray
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
}
