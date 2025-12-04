<#
.SYNOPSIS
    RDP Security Intelligence & Ultra Monitoring System v3.0
    Kapsamli RDP Guvenlik Izleme ve Loglama Sistemi
    
.DESCRIPTION
    Bu script asagidaki ozellikleri saglar:
    - Tum RDP baglantilarini loglar (basarili/basarisiz)
    - IP adresinden GeoIP bilgisi ceker (ulke, sehir, ISP)
    - Oturum suresini takip eder
    - Kullanici aktivitelerini kaydeder (acilan programlar, dosyalar)
    - Brute-force saldiri tespiti
    - Otomatik IP engelleme (Windows Firewall)
    - Whitelist destegi (guvenli IP'ler icin alert yok)
    - Rate limiting (dakikada max deneme kontrolu)
    - Supheli process tespiti (mimikatz, psexec vs.)
    - Hedeflenen kullanici adi analizi
    - Real-time alerting (Telegram)
    - Gunluk/haftalik HTML raporlama
    
.AUTHOR
    Furkan Dincer
    
.VERSION
    3.0.0
    
.NOTES
    Windows Server 2012 R2/2016/2019/2022 uyumlu
    PowerShell 5.1+ gerektirir
    Yonetici haklari ile calistirilmalidir
    
.LINK
    https://github.com/frkndncr/rdp-security-intelligence
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

# ==================== WEEKLY/MONTHLY REPORTS ====================

function New-WeeklyReport {
    $reportDate = Get-Date -Format "yyyy-MM-dd"
    $weekStart = (Get-Date).AddDays(-7)
    $reportPath = Join-Path $Config.ReportPath "weekly_report_$reportDate.html"
    
    Write-Host "[*] Haftalik rapor olusturuluyor..." -ForegroundColor Yellow
    
    # Son 7 gunun verilerini topla
    $allConnections = @()
    $allAlerts = @()
    
    for ($i = 0; $i -lt 7; $i++) {
        $date = (Get-Date).AddDays(-$i).ToString("yyyy-MM-dd")
        Write-Host "  - $date okunuyor..." -ForegroundColor Gray
        
        # Connection loglari
        $connFile = Join-Path $Config.ConnectionLogPath "connections_$date.json"
        if (Test-Path $connFile) {
            Get-Content $connFile -ErrorAction SilentlyContinue | ForEach-Object {
                try { $allConnections += ($_ | ConvertFrom-Json) } catch { }
            }
        }
        
        # Alert loglari
        $alertFile = Join-Path $Config.AlertLogPath "alerts_$date.json"
        if (Test-Path $alertFile) {
            Get-Content $alertFile -ErrorAction SilentlyContinue | ForEach-Object {
                try { $allAlerts += ($_ | ConvertFrom-Json) } catch { }
            }
        }
    }
    
    Write-Host "  - Veriler analiz ediliyor..." -ForegroundColor Gray
    
    # Gunluk dagilim
    $dailyStats = @{}
    for ($i = 6; $i -ge 0; $i--) {
        $date = (Get-Date).AddDays(-$i).ToString("yyyy-MM-dd")
        $dailyStats[$date] = @{ Success = 0; Failed = 0 }
    }
    
    foreach ($conn in $allConnections) {
        try {
            $date = ([DateTime]$conn.Timestamp).ToString("yyyy-MM-dd")
            if ($dailyStats.ContainsKey($date)) {
                if ($conn.Data.EventType -eq "SuccessfulLogon") {
                    $dailyStats[$date].Success++
                }
                else {
                    $dailyStats[$date].Failed++
                }
            }
        }
        catch { }
    }
    
    # Unique saldirgan IP'ler
    $attackerIPs = @{}
    foreach ($conn in $allConnections) {
        if ($conn.Data.EventType -eq "FailedLogon" -and $conn.Data.SourceIP) {
            $ip = $conn.Data.SourceIP
            if (-not $attackerIPs.ContainsKey($ip)) {
                $attackerIPs[$ip] = @{ Count = 0; Country = $conn.Data.Country }
            }
            $attackerIPs[$ip].Count++
        }
    }
    $topAttackers = $attackerIPs.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 15
    
    # Hedeflenen kullanici adlari - log dosyalarindan al (event log yerine)
    $userStats = @{}
    foreach ($conn in $allConnections) {
        if ($conn.Data.EventType -eq "FailedLogon" -and $conn.Data.Username) {
            $user = $conn.Data.Username.Split('\')[-1]  # Domain kismini at
            if (-not $userStats.ContainsKey($user)) { $userStats[$user] = 0 }
            $userStats[$user]++
        }
    }
    $topUsers = $userStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    
    Write-Host "  - HTML olusturuluyor..." -ForegroundColor Gray
    
    # HTML olustur
    $dailyChartHtml = ""
    $maxVal = ($dailyStats.Values | ForEach-Object { $_.Success + $_.Failed } | Measure-Object -Maximum).Maximum
    if ($maxVal -eq 0) { $maxVal = 1 }
    
    foreach ($day in ($dailyStats.Keys | Sort-Object)) {
        $dayName = ([DateTime]$day).ToString("ddd")
        $total = $dailyStats[$day].Success + $dailyStats[$day].Failed
        $height = [math]::Round(($total / $maxVal) * 100)
        $dailyChartHtml += "<div class='day-bar'><div class='day-fill' style='height: $height%' title='$($dayName): $total'></div><span class='day-label'>$dayName</span></div>`n"
    }
    
    $attackerRows = ""
    $rank = 1
    foreach ($a in $topAttackers) {
        $attackerRows += "<tr><td>$rank</td><td><strong>$($a.Key)</strong></td><td>$($a.Value.Country)</td><td class='attempt-count'>$($a.Value.Count)</td></tr>`n"
        $rank++
    }
    
    $userRows = ""
    $rank = 1
    foreach ($u in $topUsers) {
        $isCommon = $u.Key -in @("administrator", "admin", "sa", "root", "user", "guest", "test")
        $class = if ($isCommon) { "common-user" } else { "real-user" }
        $userRows += "<tr class='$class'><td>$rank</td><td><strong>$($u.Key)</strong></td><td class='attempt-count'>$($u.Value)</td></tr>`n"
        $rank++
    }
    
    $totalSuccess = 0
    $totalFailed = 0
    foreach ($day in $dailyStats.Keys) {
        $totalSuccess += $dailyStats[$day].Success
        $totalFailed += $dailyStats[$day].Failed
    }
    $uniqueAttackers = $attackerIPs.Count
    
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <title>RDP Security Weekly Report - $reportDate</title>
    <meta charset="UTF-8">
    <style>
        :root { --primary: #667eea; --success: #48bb78; --danger: #f56565; --warning: #ed8936; --dark: #2d3748; --light: #f7fafc; --gray: #718096; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: rgba(255,255,255,0.95); border-radius: 16px; padding: 30px; margin-bottom: 20px; }
        .header h1 { font-size: 1.8em; color: var(--dark); }
        .header h1::before { content: ''; display: inline-block; width: 8px; height: 32px; background: linear-gradient(180deg, #667eea 0%, #f56565 100%); border-radius: 4px; margin-right: 15px; }
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; border-radius: 16px; padding: 25px; text-align: center; }
        .stat-card h3 { font-size: 2.5em; margin-bottom: 5px; }
        .stat-card.success h3 { color: var(--success); }
        .stat-card.danger h3 { color: var(--danger); }
        .stat-card.warning h3 { color: var(--warning); }
        .stat-card.info h3 { color: var(--primary); }
        .section { background: white; border-radius: 16px; padding: 25px; margin-bottom: 20px; }
        .section-title { font-size: 1.2em; color: var(--dark); margin-bottom: 20px; border-bottom: 2px solid var(--light); padding-bottom: 10px; }
        .daily-chart { display: flex; align-items: flex-end; height: 150px; gap: 10px; justify-content: space-around; }
        .day-bar { display: flex; flex-direction: column; align-items: center; flex: 1; height: 100%; }
        .day-fill { width: 100%; background: linear-gradient(180deg, var(--danger) 0%, var(--warning) 100%); border-radius: 8px 8px 0 0; min-height: 5px; }
        .day-label { margin-top: 10px; font-weight: 600; color: var(--gray); }
        table { width: 100%; border-collapse: collapse; }
        th { background: var(--dark); color: white; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #edf2f7; }
        .attempt-count { font-weight: 700; color: var(--danger); }
        .common-user { background: #fffaf0; }
        .real-user { background: #fff5f5; }
        .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .footer { text-align: center; padding: 20px; color: rgba(255,255,255,0.7); }
        @media (max-width: 900px) { .summary-grid, .two-col { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Haftalik Guvenlik Raporu</h1>
            <p style="color: var(--gray); margin-top: 10px;">$env:COMPUTERNAME | $((Get-Date).AddDays(-7).ToString("dd.MM.yyyy")) - $((Get-Date).ToString("dd.MM.yyyy"))</p>
        </div>
        
        <div class="summary-grid">
            <div class="stat-card success"><h3>$totalSuccess</h3><p>Basarili Giris</p></div>
            <div class="stat-card danger"><h3>$totalFailed</h3><p>Basarisiz Deneme</p></div>
            <div class="stat-card warning"><h3>$uniqueAttackers</h3><p>Farkli Saldirgan</p></div>
            <div class="stat-card info"><h3>$($allAlerts.Count)</h3><p>Guvenlik Alarmi</p></div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Gunluk Dagilim</h2>
            <div class="daily-chart">$dailyChartHtml</div>
        </div>
        
        <div class="two-col">
            <div class="section">
                <h2 class="section-title">En Cok Saldiran IP'ler</h2>
                <table>
                    <tr><th>#</th><th>IP Adresi</th><th>Ulke</th><th>Deneme</th></tr>
                    $attackerRows
                </table>
            </div>
            <div class="section">
                <h2 class="section-title">Hedeflenen Kullanici Adlari</h2>
                <table>
                    <tr><th>#</th><th>Kullanici Adi</th><th>Deneme</th></tr>
                    $userRows
                </table>
                <p style="margin-top: 15px; font-size: 0.85em; color: var(--gray);">
                    <span style="background: #fffaf0; padding: 2px 8px; border-radius: 4px;">Sari</span> = Yaygin kullanici adi &nbsp;
                    <span style="background: #fff5f5; padding: 2px 8px; border-radius: 4px;">Kirmizi</span> = Gercek hesap olabilir
                </p>
            </div>
        </div>
        
        <div class="footer">RDP Security Intelligence - Haftalik Rapor</div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "[+] Haftalik rapor olusturuldu: $reportPath" -ForegroundColor Green
    return $reportPath
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
    
    # Unique IP'ler icin GeoIP bilgisi
    $uniqueIPs = ($connections | Select-Object -ExpandProperty SourceIP -Unique) | Where-Object { $_ }
    $geoData = @{}
    foreach ($ip in $uniqueIPs) {
        if ($ip -and $ip -ne "-") {
            $geoData[$ip] = Get-GeoIPInfo -IPAddress $ip
        }
    }
    
    # Ulke bazli istatistik
    $countryStats = @{}
    foreach ($conn in $failedLogons) {
        $geo = $geoData[$conn.SourceIP]
        $country = if ($geo -and $geo.Country) { $geo.Country } else { "Unknown" }
        if (-not $countryStats[$country]) { $countryStats[$country] = 0 }
        $countryStats[$country]++
    }
    $topCountries = $countryStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    
    # En cok saldiran IP'ler
    $ipStats = @{}
    foreach ($conn in $failedLogons) {
        $ip = $conn.SourceIP
        if (-not $ipStats[$ip]) { $ipStats[$ip] = 0 }
        $ipStats[$ip]++
    }
    $topAttackers = $ipStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    
    # Top Attackers tablosu
    $topAttackersRows = ""
    $rank = 1
    foreach ($attacker in $topAttackers) {
        $geo = $geoData[$attacker.Key]
        $country = if ($geo -and $geo.Country) { $geo.Country } else { "Unknown" }
        $city = if ($geo -and $geo.City) { $geo.City } else { "-" }
        $isp = if ($geo -and $geo.ISP) { $geo.ISP } else { "-" }
        $flagClass = if ($country -in @("China", "Russia", "North Korea", "Iran")) { "danger-row" } else { "" }
        $topAttackersRows += "<tr class='$flagClass'><td>$rank</td><td><strong>$($attacker.Key)</strong></td><td>$country</td><td>$city</td><td>$isp</td><td class='attempt-count'>$($attacker.Value)</td></tr>`n"
        $rank++
    }
    
    # Ulke istatistik HTML
    $countryStatsHtml = ""
    foreach ($c in $topCountries) {
        $percent = if ($failedLogons.Count -gt 0) { [math]::Round(($c.Value / $failedLogons.Count) * 100, 1) } else { 0 }
        $countryStatsHtml += "<div class='country-bar'><span class='country-name'>$($c.Key)</span><div class='bar-container'><div class='bar' style='width: $percent%'></div></div><span class='country-count'>$($c.Value) (%$percent)</span></div>`n"
    }
    
    # Basarili giris tablosu
    $successTableRows = ""
    $successfulLogons | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object {
        $geo = $geoData[$_.SourceIP]
        $country = if ($geo -and $geo.Country) { $geo.Country } else { "Unknown" }
        $city = if ($geo -and $geo.City) { $geo.City } else { "-" }
        $isp = if ($geo -and $geo.ISP) { $geo.ISP } else { "-" }
        $successTableRows += "<tr><td>$($_.TimeCreated.ToString('dd.MM.yyyy HH:mm:ss'))</td><td>$($_.Domain)\$($_.Username)</td><td>$($_.SourceIP)</td><td>$country, $city</td><td>$isp</td></tr>`n"
    }
    
    # Aktif oturum tablosu
    $sessionTableRows = ""
    $sessions | ForEach-Object {
        $stateClass = if ($_.State -eq "Active") { "state-active" } else { "state-disc" }
        $sessionTableRows += "<tr><td><strong>$($_.Username)</strong></td><td>$($_.SessionID)</td><td class='$stateClass'>$($_.State)</td><td>$($_.IdleTime)</td><td>$($_.LogonTime)</td></tr>`n"
    }
    
    # Alert tablosu - gruplu
    $alertGroups = @{}
    foreach ($alert in $bruteForceAnalysis.Alerts) {
        $key = $alert.IP
        if (-not $alertGroups[$key]) {
            $alertGroups[$key] = @{ IP = $alert.IP; Country = $alert.Country; TotalAttempts = 0; AlertCount = 0 }
        }
        $alertGroups[$key].TotalAttempts += $alert.AttemptCount
        $alertGroups[$key].AlertCount++
    }
    $groupedAlerts = $alertGroups.Values | Sort-Object TotalAttempts -Descending | Select-Object -First 15
    
    $alertsHtml = ""
    if ($groupedAlerts.Count -gt 0) {
        foreach ($a in $groupedAlerts) {
            $geo = $geoData[$a.IP]
            $isp = if ($geo -and $geo.ISP) { $geo.ISP } else { "-" }
            $severityClass = if ($a.TotalAttempts -gt 1000) { "alert-critical" } elseif ($a.TotalAttempts -gt 100) { "alert-high" } else { "alert-medium" }
            $alertsHtml += "<div class='alert-card $severityClass'><div class='alert-ip'>$($a.IP)</div><div class='alert-detail'><span class='alert-country'>$($a.Country)</span><span class='alert-isp'>$isp</span></div><div class='alert-count'>$($a.TotalAttempts) deneme</div></div>`n"
        }
    } else {
        $alertsHtml = "<div class='no-alerts'>Son 24 saatte brute-force saldirisi tespit edilmedi.</div>"
    }
    
    # Zaman bazli analiz (saatlik dagilim)
    $hourlyStats = @{}
    0..23 | ForEach-Object { $hourlyStats[$_] = 0 }
    foreach ($conn in $failedLogons) {
        $hour = $conn.TimeCreated.Hour
        $hourlyStats[$hour]++
    }
    $maxHourly = ($hourlyStats.Values | Measure-Object -Maximum).Maximum
    if ($maxHourly -eq 0) { $maxHourly = 1 }
    
    $hourlyChartHtml = ""
    0..23 | ForEach-Object {
        $height = [math]::Round(($hourlyStats[$_] / $maxHourly) * 100)
        $hourlyChartHtml += "<div class='hour-bar'><div class='hour-fill' style='height: $height%' title='$($hourlyStats[$_]) deneme'></div><span class='hour-label'>$_</span></div>`n"
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <title>RDP Security Report - $reportDate</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #667eea;
            --primary-dark: #5a67d8;
            --success: #48bb78;
            --danger: #f56565;
            --warning: #ed8936;
            --info: #4299e1;
            --dark: #2d3748;
            --light: #f7fafc;
            --gray: #718096;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header {
            background: rgba(255,255,255,0.95);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .header h1 {
            font-size: 1.8em;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header h1::before {
            content: '';
            display: inline-block;
            width: 8px;
            height: 32px;
            background: linear-gradient(180deg, var(--primary) 0%, var(--danger) 100%);
            border-radius: 4px;
        }
        
        .server-info {
            background: var(--light);
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 0.9em;
            color: var(--gray);
        }
        
        .server-info strong { color: var(--dark); }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            border-radius: 16px;
            padding: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
        }
        
        .stat-card.success::before { background: var(--success); }
        .stat-card.danger::before { background: var(--danger); }
        .stat-card.warning::before { background: var(--warning); }
        .stat-card.info::before { background: var(--info); }
        
        .stat-card h3 { font-size: 2.5em; font-weight: 700; margin-bottom: 5px; }
        .stat-card.success h3 { color: var(--success); }
        .stat-card.danger h3 { color: var(--danger); }
        .stat-card.warning h3 { color: var(--warning); }
        .stat-card.info h3 { color: var(--info); }
        .stat-card p { color: var(--gray); font-size: 0.95em; }
        
        .section {
            background: white;
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        
        .section-title {
            font-size: 1.2em;
            color: var(--dark);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--light);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title .icon {
            width: 28px; height: 28px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
        }
        
        .icon-danger { background: #fed7d7; color: var(--danger); }
        .icon-success { background: #c6f6d5; color: var(--success); }
        .icon-info { background: #bee3f8; color: var(--info); }
        .icon-warning { background: #feebc8; color: var(--warning); }
        
        .alerts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }
        
        .alert-card {
            background: var(--light);
            border-radius: 12px;
            padding: 15px;
            border-left: 4px solid var(--warning);
        }
        
        .alert-critical { border-left-color: var(--danger); background: #fff5f5; }
        .alert-high { border-left-color: var(--warning); background: #fffaf0; }
        .alert-medium { border-left-color: var(--info); background: #ebf8ff; }
        
        .alert-ip { font-family: 'Consolas', monospace; font-weight: 600; font-size: 1.1em; color: var(--dark); }
        .alert-detail { display: flex; gap: 10px; margin: 8px 0; font-size: 0.85em; }
        .alert-country { background: var(--dark); color: white; padding: 2px 8px; border-radius: 4px; }
        .alert-isp { color: var(--gray); }
        .alert-count { font-weight: 700; color: var(--danger); font-size: 1.1em; }
        .no-alerts { text-align: center; padding: 40px; color: var(--success); font-size: 1.1em; }
        
        table { width: 100%; border-collapse: collapse; }
        th {
            background: var(--dark);
            color: white;
            padding: 14px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        th:first-child { border-radius: 8px 0 0 0; }
        th:last-child { border-radius: 0 8px 0 0; }
        td { padding: 12px; border-bottom: 1px solid #edf2f7; font-size: 0.9em; }
        tr:hover { background: #f7fafc; }
        .danger-row { background: #fff5f5; }
        .danger-row:hover { background: #fed7d7; }
        .attempt-count { font-weight: 700; color: var(--danger); font-size: 1.1em; }
        .state-active { color: var(--success); font-weight: 600; }
        .state-disc { color: var(--warning); font-weight: 600; }
        
        .country-bar { display: flex; align-items: center; margin-bottom: 12px; gap: 10px; }
        .country-name { min-width: 100px; font-weight: 500; }
        .bar-container { flex: 1; height: 24px; background: #edf2f7; border-radius: 12px; overflow: hidden; }
        .bar { height: 100%; background: linear-gradient(90deg, var(--danger) 0%, var(--warning) 100%); border-radius: 12px; }
        .country-count { min-width: 100px; text-align: right; font-weight: 600; color: var(--gray); }
        
        .hourly-chart { display: flex; align-items: flex-end; height: 120px; gap: 4px; padding: 10px 0; }
        .hour-bar { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; }
        .hour-fill { width: 100%; background: linear-gradient(180deg, var(--primary) 0%, var(--primary-dark) 100%); border-radius: 4px 4px 0 0; min-height: 2px; }
        .hour-label { font-size: 10px; color: var(--gray); margin-top: 5px; }
        
        .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
        
        .footer { text-align: center; padding: 20px; color: rgba(255,255,255,0.8); font-size: 0.9em; }
        .footer a { color: white; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-top">
                <h1>RDP Security Intelligence</h1>
                <div class="server-info">
                    <strong>$env:COMPUTERNAME</strong> | $reportDate $(Get-Date -Format "HH:mm")
                </div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="stat-card success">
                <h3>$($successfulLogons.Count)</h3>
                <p>Basarili Giris</p>
            </div>
            <div class="stat-card danger">
                <h3>$($failedLogons.Count)</h3>
                <p>Basarisiz Deneme</p>
            </div>
            <div class="stat-card info">
                <h3>$($sessions.Count)</h3>
                <p>Aktif Oturum</p>
            </div>
            <div class="stat-card warning">
                <h3>$($groupedAlerts.Count)</h3>
                <p>Tehdit Kaynagi</p>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title"><span class="icon icon-danger">!</span> En Cok Saldiran IP'ler</h2>
            <table>
                <tr><th>#</th><th>IP Adresi</th><th>Ulke</th><th>Sehir</th><th>ISP</th><th>Deneme</th></tr>
                $topAttackersRows
            </table>
        </div>
        
        <div class="two-col">
            <div class="section">
                <h2 class="section-title"><span class="icon icon-warning">*</span> Ulke Dagilimi</h2>
                $countryStatsHtml
            </div>
            <div class="section">
                <h2 class="section-title"><span class="icon icon-info">~</span> Saatlik Dagilim</h2>
                <div class="hourly-chart">$hourlyChartHtml</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title"><span class="icon icon-danger">!</span> Guvenlik Uyarilari</h2>
            <div class="alerts-grid">$alertsHtml</div>
        </div>
        
        <div class="section">
            <h2 class="section-title"><span class="icon icon-success">+</span> Basarili Girisler</h2>
            <table>
                <tr><th>Zaman</th><th>Kullanici</th><th>IP Adresi</th><th>Konum</th><th>ISP</th></tr>
                $successTableRows
            </table>
        </div>
        
        <div class="section">
            <h2 class="section-title"><span class="icon icon-info">i</span> Aktif Oturumlar</h2>
            <table>
                <tr><th>Kullanici</th><th>Session ID</th><th>Durum</th><th>Bosta</th><th>Giris Zamani</th></tr>
                $sessionTableRows
            </table>
        </div>
        
        <div class="footer">
            RDP Security Intelligence System | <a href="https://github.com/frkndncr/rdp-security-intelligence">GitHub</a>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-SecurityLog -LogType "Alert" -Message "Daily report generated" -Severity "INFO" -Data @{Path = $reportPath}
    Write-Host "[+] Rapor olusturuldu: $reportPath" -ForegroundColor Green
    return $reportPath
}

# ==================== MONITORING SERVICE ====================

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
                ($_.Properties[8].Value -eq 10) -or ($_.Properties[10].Value -eq 10)
            }
            
            foreach ($event in $newEvents) {
                $isSuccess = $event.Id -eq 4624
                $sourceIP = if ($isSuccess) { $event.Properties[18].Value } else { $event.Properties[19].Value }
                $username = $event.Properties[5].Value
                $domain = $event.Properties[6].Value
                
                # Whitelist kontrolu
                $isWhitelisted = Test-WhitelistedIP -IPAddress $sourceIP
                
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
