# 🛡️ RDP Security Intelligence

<div align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-2016|2019|2022-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0-orange?style=for-the-badge)

**Windows sunuculariniz icin 7/24 RDP guvenlik izleme ve bildirim sistemi**

*Her baglantida aninda haber alin - Ulke, sehir, ISP bilgisiyle birlikte*

[Ozellikler](#-ozellikler) • [Kurulum](#-kurulum) • [Kullanim](#-kullanim) • [Yapilandirma](#%EF%B8%8F-yapilandirma) • [SSS](#-sss)

---

</div>

## 🎯 Problem

Sunuculariniza **kim**, **nereden**, **ne zaman** baglandigini biliyor musunuz?

Cogu sistem yoneticisi Event Viewer'dan kontrol eder - ama kac kisi bunu her gun yapiyor?

**RDP Security Intelligence** bu sorunu cozer:

- ✅ Her baglantida telefonunuza bildirim
- ✅ Saldiri girisimleri aninda tespit
- ✅ Kurulum sadece 5 dakika

---

## 📱 Telegram Bildirimi

Her RDP girisinde su sekilde bildirim alirsiniz:

```
[i] RDP Security Alert [i]
========================
Server: PROD-DC01
Time: 2024-01-15 09:15:32
Severity: INFO

RDP Login Successful

- User : DOMAIN\furkan
- IP : 85.105.xx.xx
- Country : Turkey
- City : Istanbul
- ISP : Turk Telekom
========================
```

Basarisiz giris veya supheli ulkeden baglanti olursa:

```
[!!!] RDP Security Alert [!!!]
========================
Server: PROD-DC01
Time: 2024-01-15 14:32:45
Severity: CRITICAL

SUSPICIOUS COUNTRY ALERT

- User : administrator
- IP : 185.220.101.45
- Country : Russia
- City : Moscow
- ISP : Suspicious Hosting
========================
```

---

## ✨ Ozellikler

| Ozellik | Aciklama |
|:--------|:---------|
| 📡 **Anlik Telegram Bildirimi** | Basarili ve basarisiz tum girisler icin aninda bildirim |
| 🌍 **GeoIP Istihbarati** | Her IP icin ulke, sehir, ISP, koordinat bilgisi |
| 🚨 **Brute-Force Tespiti** | Belirlenen esik asildiginda otomatik uyari |
| ⚠️ **Supheli Ulke Alarmi** | Tanimli ulkelerden baglantida CRITICAL alert |
| 📊 **Gunluk HTML Rapor** | Her gun 23:55'te otomatik guvenlik raporu |
| 👥 **Oturum Takibi** | Aktif oturumlar ve sureleri |
| 🔄 **7/24 Servis** | Windows servisi olarak surekli calisma |
| 💪 **Otomatik Kurtarma** | Cokerse 1 dakika icinde yeniden baslatma |
| 🧹 **Log Temizligi** | Eski loglar otomatik silinir (varsayilan 90 gun) |

---

## 🚀 Kurulum

### Adim 1: Telegram Bot Olustur

1. Telegram'da **@BotFather**'a mesaj at
2. `/newbot` komutunu gonder
3. Bot adini ve kullanici adini gir
4. Sana verilen **TOKEN**'i kopyala

5. **@userinfobot**'a mesaj at
6. `/start` komutunu gonder  
7. Sana verilen **Chat ID**'yi kopyala

### Adim 2: Script'i Yapilandir

Script'i indir ve asagidaki satirlari kendi bilgilerinle degistir:

```powershell
TelegramBotToken    = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
TelegramChatID      = "987654321"
```

### Adim 3: Kur ve Calistir

PowerShell'i **Yonetici olarak** ac:

```powershell
# Script'in oldugu dizine git
cd C:\Scripts

# Script'i yukle
. .\RDP-Security-Intelligence.ps1

# Telegram baglantisinini test et
Test-TelegramConnection

# Servisi kur
Install-MonitoringScheduledTasks
```

### Adim 4: Dogrula

```powershell
# Servis durumunu kontrol et
Get-MonitoringServiceStatus
```

Cikti soyle olmali:
```
Task: RDP Security Monitoring Service
   Durum: [+] CALISIYOR
```

**Kurulum tamamlandi!** 🎉

---

## 📋 Kullanim

### Temel Komutlar

```powershell
# Hizli guvenlik ozeti (son 24 saat)
Get-QuickSecurityStatus

# Tum RDP baglantilarini listele
Get-RDPConnections

# Aktif oturumlari gor
Get-ActiveRDPSessions

# Brute-force analizi
Get-FailedLoginAnalysis

# Servis durumu
Get-MonitoringServiceStatus

# Manuel HTML rapor olustur
New-DailyReport

# Telegram baglantisini test et
Test-TelegramConnection
```

### Ornek Ciktilar

**Get-QuickSecurityStatus:**
```
============================================================
            RDP SECURITY QUICK STATUS
============================================================

Son 24 Saat:
   [+] Basarili Giris : 12
   [-] Basarisiz      : 847
   [*] Aktif Oturum   : 2
   [!] Uyari          : 3

Aktif Oturumlar:
   - DOMAIN\furkan (ID: 2, Active)
   - DOMAIN\admin (ID: 3, Active)

Uyarilar:
   [!] 185.220.101.45 (Russia) - 156 deneme
   [!] 45.227.255.99 (China) - 89 deneme
============================================================
```

---

## ⚙️ Yapilandirma

Script'in basindaki `$Config` bolumunu duzenleyebilirsiniz:

```powershell
$Config = @{
    # === TELEGRAM ===
    EnableTelegramAlert = $true
    TelegramBotToken    = "YOUR_BOT_TOKEN"
    TelegramChatID      = "YOUR_CHAT_ID"
    
    # === GUVENLIK ESIKLERI ===
    FailedLoginThreshold    = 5         # X basarisiz giristen sonra alert
    FailedLoginTimeWindow   = 300       # Zaman penceresi (saniye)
    SuspiciousCountries     = @("CN", "RU", "KP", "IR")  # Supheli ulkeler
    
    # === LOG AYARLARI ===
    LogRetentionDays        = 90        # Kac gun log saklansin
}
```

### Supheli Ulke Kodlari

| Kod | Ulke |
|-----|------|
| CN | Cin |
| RU | Rusya |
| KP | Kuzey Kore |
| IR | Iran |

Eklemek icin: `SuspiciousCountries = @("CN", "RU", "KP", "IR", "VN", "BR")`

---

## 📁 Log Yapisi

```
C:\RDP-Security-Logs\
├── Connections\          # Baglanti loglari (JSON)
│   └── connections_2024-01-15.json
├── Sessions\             # Oturum loglari
│   └── sessions_2024-01-15.json
├── Activity\             # Kullanici aktiviteleri
│   └── activity_2024-01-15.json
├── Alerts\               # Guvenlik uyarilari
│   └── alerts_2024-01-15.json
├── Reports\              # HTML raporlar
│   └── daily_report_2024-01-15.html
└── RDP-Security-Intelligence.ps1   # Script kopyasi
```

---

## 🔧 Scheduled Tasks

Kurulum sonrasi 3 adet Windows Task olusturulur:

| Task | Calisma Zamani | Aciklama |
|------|----------------|----------|
| RDP Security Monitoring Service | 7/24 | Ana izleme servisi |
| RDP Security Daily Report | Her gun 23:55 | HTML rapor olusturur |
| RDP Security Log Cleanup | Pazar 03:00 | Eski loglari siler |

Kontrol etmek icin:
```powershell
Get-MonitoringServiceStatus
# veya
Get-ScheduledTask | Where-Object {$_.TaskName -like "RDP Security*"}
```

---

## ❓ SSS

**S: Script calismiyor, hata aliorum**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**S: Telegram bildirimi gelmiyor**
- Bot token ve Chat ID'yi kontrol et
- `Test-TelegramConnection` komutunu calistir
- Sunucudan internete erisimi kontrol et

**S: Event bulunamiyor diyor**
- PowerShell'i **Yonetici** olarak calistir
- RDP'nin sunucuda etkin oldugunu kontrol et

**S: Servisi durdurmak istiyorum**
```powershell
Stop-ScheduledTask -TaskName "RDP Security Monitoring Service"
```

**S: Tamamen kaldirmak istiyorum**
```powershell
Unregister-ScheduledTask -TaskName "RDP Security Monitoring Service" -Confirm:$false
Unregister-ScheduledTask -TaskName "RDP Security Daily Report" -Confirm:$false
Unregister-ScheduledTask -TaskName "RDP Security Log Cleanup" -Confirm:$false
Remove-Item -Path "C:\RDP-Security-Logs" -Recurse -Force
```

---

## 📋 Gereksinimler

- Windows Server 2016 / 2019 / 2022 veya Windows 10/11
- PowerShell 5.1+
- Yonetici (Administrator) yetkisi
- Internet erisimi (GeoIP ve Telegram icin)

---

## 📝 Lisans

MIT License - Detaylar icin [LICENSE](LICENSE) dosyasina bakin.

---

## 👤 Gelistirici

**Furkan Dincer**

[![GitHub](https://img.shields.io/badge/GitHub-furkandincer-181717?style=flat&logo=github)](https://github.com/furkandincer)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-furkandincer-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/furkandincer)

---

<div align="center">

⭐ **Begendiniz mi? Yildiz birakin!** ⭐

</div>
