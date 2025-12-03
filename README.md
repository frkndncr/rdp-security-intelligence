# 🛡️ RDP Security Intelligence

<div align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-2016|2019|2022-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0-orange?style=for-the-badge)

**Windows sunucularınız için 7/24 RDP güvenlik izleme ve bildirim sistemi**

*Her bağlantıda anında haber alın - Ülke, şehir, ISP bilgisiyle birlikte*

[Özellikler](#-özellikler) • [Kurulum](#-kurulum) • [Kullanım](#-kullanım) • [Yapılandırma](#%EF%B8%8F-yapılandırma) • [SSS](#-sss)

---

</div>

## 🎯 Problem

Sunucularınıza **kim**, **nereden**, **ne zaman** bağlandığını biliyor musunuz?

Çoğu sistem yöneticisi Event Viewer'dan kontrol eder - ama kaç kişi bunu her gün yapıyor?

**RDP Security Intelligence** bu sorunu çözer:

- ✅ Her bağlantıda telefonunuza bildirim
- ✅ Saldırı girişimleri anında tespit
- ✅ Kurulum sadece 5 dakika

---

## 📱 Telegram Bildirimi

Her RDP girişinde şu şekilde bildirim alırsınız:

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

Başarısız giriş veya şüpheli ülkeden bağlantı olursa:

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

## ✨ Özellikler

| Özellik | Açıklama |
|:--------|:---------|
| 📡 **Anlık Telegram Bildirimi** | Başarılı ve başarısız tüm girişler için anında bildirim |
| 🌍 **GeoIP İstihbaratı** | Her IP için ülke, şehir, ISP, koordinat bilgisi |
| 🚨 **Brute-Force Tespiti** | Belirlenen eşik aşıldığında otomatik uyarı |
| ⚠️ **Şüpheli Ülke Alarmı** | Tanımlı ülkelerden bağlantıda CRITICAL alert |
| 📊 **Günlük HTML Rapor** | Her gün 23:55'te otomatik güvenlik raporu |
| 👥 **Oturum Takibi** | Aktif oturumlar ve süreleri |
| 🔄 **7/24 Servis** | Windows servisi olarak sürekli çalışma |
| 💪 **Otomatik Kurtarma** | Çökerse 1 dakika içinde yeniden başlatma |
| 🧹 **Log Temizliği** | Eski loglar otomatik silinir (varsayılan 90 gün) |

---

## 🚀 Kurulum

### Adım 1: Telegram Bot Oluştur

1. Telegram'da **@BotFather**'a mesaj at
2. `/newbot` komutunu gönder
3. Bot adını ve kullanıcı adını gir
4. Sana verilen **TOKEN**'ı kopyala

5. **@userinfobot**'a mesaj at
6. `/start` komutunu gönder  
7. Sana verilen **Chat ID**'yi kopyala

### Adım 2: Script'i Yapılandır

Script'i indir ve aşağıdaki satırları kendi bilgilerinle değiştir:

```powershell
TelegramBotToken    = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
TelegramChatID      = "987654321"
```

### Adım 3: Kur ve Çalıştır

PowerShell'i **Yönetici olarak** aç:

```powershell
# Script'in olduğu dizine git
cd C:\Scripts

# Script'i yükle
. .\RDP-Security-Intelligence.ps1

# Telegram bağlantısını test et
Test-TelegramConnection

# Servisi kur
Install-MonitoringScheduledTasks
```

### Adım 4: Doğrula

```powershell
# Servis durumunu kontrol et
Get-MonitoringServiceStatus
```

Çıktı şöyle olmalı:
```
Task: RDP Security Monitoring Service
   Durum: [+] CALISIYOR
```

**Kurulum tamamlandı!** 🎉

---

## 📋 Kullanım

### Temel Komutlar

```powershell
# Hızlı güvenlik özeti (son 24 saat)
Get-QuickSecurityStatus

# Tüm RDP bağlantılarını listele
Get-RDPConnections

# Aktif oturumları gör
Get-ActiveRDPSessions

# Brute-force analizi
Get-FailedLoginAnalysis

# Servis durumu
Get-MonitoringServiceStatus

# Manuel HTML rapor oluştur
New-DailyReport

# Telegram bağlantısını test et
Test-TelegramConnection
```

### Örnek Çıktılar

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

## ⚙️ Yapılandırma

Script'in başındaki `$Config` bölümünü düzenleyebilirsiniz:

```powershell
$Config = @{
    # === TELEGRAM ===
    EnableTelegramAlert = $true
    TelegramBotToken    = "YOUR_BOT_TOKEN"
    TelegramChatID      = "YOUR_CHAT_ID"
    
    # === GÜVENLİK EŞİKLERİ ===
    FailedLoginThreshold    = 5         # X başarısız girişten sonra alert
    FailedLoginTimeWindow   = 300       # Zaman penceresi (saniye)
    SuspiciousCountries     = @("CN", "RU", "KP", "IR")  # Şüpheli ülkeler
    
    # === LOG AYARLARI ===
    LogRetentionDays        = 90        # Kaç gün log saklansın
}
```

### Şüpheli Ülke Kodları

| Kod | Ülke |
|-----|------|
| CN | Çin |
| RU | Rusya |
| KP | Kuzey Kore |
| IR | İran |

Eklemek için: `SuspiciousCountries = @("CN", "RU", "KP", "IR", "VN", "BR")`

---

## 📁 Log Yapısı

```
C:\RDP-Security-Logs\
├── Connections\          # Bağlantı logları (JSON)
│   └── connections_2024-01-15.json
├── Sessions\             # Oturum logları
│   └── sessions_2024-01-15.json
├── Activity\             # Kullanıcı aktiviteleri
│   └── activity_2024-01-15.json
├── Alerts\               # Güvenlik uyarıları
│   └── alerts_2024-01-15.json
├── Reports\              # HTML raporlar
│   └── daily_report_2024-01-15.html
└── RDP-Security-Intelligence.ps1   # Script kopyası
```

---

## 🔧 Scheduled Tasks

Kurulum sonrası 3 adet Windows Task oluşturulur:

| Task | Çalışma Zamanı | Açıklama |
|------|----------------|----------|
| RDP Security Monitoring Service | 7/24 | Ana izleme servisi |
| RDP Security Daily Report | Her gün 23:55 | HTML rapor oluşturur |
| RDP Security Log Cleanup | Pazar 03:00 | Eski logları siler |

Kontrol etmek için:
```powershell
Get-MonitoringServiceStatus
# veya
Get-ScheduledTask | Where-Object {$_.TaskName -like "RDP Security*"}
```

---

## ❓ SSS

**S: Script çalışmıyor, hata alıyorum**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**S: Telegram bildirimi gelmiyor**
- Bot token ve Chat ID'yi kontrol et
- `Test-TelegramConnection` komutunu çalıştır
- Sunucudan internete erişimi kontrol et

**S: Event bulunamıyor diyor**
- PowerShell'i **Yönetici** olarak çalıştır
- RDP'nin sunucuda etkin olduğunu kontrol et

**S: Servisi durdurmak istiyorum**
```powershell
Stop-ScheduledTask -TaskName "RDP Security Monitoring Service"
```

**S: Tamamen kaldırmak istiyorum**
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
- Yönetici (Administrator) yetkisi
- İnternet erişimi (GeoIP ve Telegram için)

---

## 📝 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 👤 Geliştirici

**Furkan Dinçer**

[![GitHub](https://img.shields.io/badge/GitHub-furkandincer-181717?style=flat&logo=github)](https://github.com/furkandincer)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-furkandincer-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/furkandincer)

---

<div align="center">

⭐ **Beğendiniz mi? Yıldız bırakın!** ⭐

</div>
