# 🛡️ RDP Security Intelligence v3.0

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2012%20R2%2B-green.svg)](https://www.microsoft.com/en-us/windows-server)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0.0-red.svg)](https://github.com/furkandncer/RDP-Security-Intelligence)

**Kapsamlı RDP Güvenlik İzleme, Koruma ve Raporlama Sistemi**

Windows Server'larınızı RDP brute-force saldırılarından koruyun. Gerçek zamanlı izleme, otomatik IP engelleme, detaylı raporlama ve Telegram bildirimleri ile tam kontrol sağlayın.

---

## 🆕 V3.0 Yenilikler

| Özellik | Açıklama |
|---------|----------|
| 🚫 **Otomatik IP Engelleme** | Brute-force yapan IP'leri Windows Firewall ile otomatik engeller |
| ✅ **Whitelist Desteği** | CIDR notation ile güvenli IP aralıkları tanımlayın |
| ⏱️ **Rate Limiting** | Dakika başına deneme limiti aşıldığında alarm |
| 🔍 **Şüpheli Process Tespiti** | mimikatz, psexec gibi tehlikeli araçları tespit eder |
| 👤 **Kullanıcı Adı Analizi** | Hangi kullanıcı adlarının hedef alındığını görün |
| 📊 **Haftalık Raporlar** | 7 günlük detaylı HTML raporları |
| 🎨 **Modern UI Raporlar** | Dark tema, grafikler, responsive tasarım |

---

## ✨ Tüm Özellikler

### 🔒 Güvenlik
- Otomatik IP engelleme (Windows Firewall)
- Whitelist desteği (CIDR notation)
- Rate limiting (dakika başına limit)
- Şüpheli process tespiti
- Brute-force saldırı algılama
- Tehlikeli ülke uyarıları (CN, RU, KP, IR)

### 📍 İstihbarat
- GeoIP entegrasyonu (ülke, şehir, ISP)
- IP bazlı saldırı istatistikleri
- Hedeflenen kullanıcı adı analizi
- Saatlik/günlük saldırı dağılımı

### 📱 Bildirimler
- Telegram real-time alertler
- Severity bazlı bildirimler (INFO, WARNING, CRITICAL)
- Başarılı giriş bildirimleri
- Engellenen IP bildirimleri

### 📈 Raporlama
- **Günlük Rapor**: Top saldırganlar, ülke dağılımı, saatlik grafik
- **Haftalık Rapor**: 7 günlük trend, karşılaştırmalı analiz
- Modern dark tema tasarım
- Responsive (mobil uyumlu)
- HTML formatında, tarayıcıda açılır

---

## 📋 Gereksinimler

- Windows Server 2012 R2 / 2016 / 2019 / 2022 / 2025
- PowerShell 5.1 veya üzeri
- Yönetici (Administrator) hakları
- İnternet bağlantısı (GeoIP ve Telegram için)

---

## 🚀 Kurulum

### 1. Script'i İndirin

```powershell
# Dizin oluştur
New-Item -ItemType Directory -Path "C:\RDP-Security-Logs" -Force

# GitHub'dan indirin
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/furkandncer/RDP-Security-Intelligence/main/RDP-Security-Intelligence.ps1" -OutFile "C:\RDP-Security-Logs\RDP-Security-Intelligence.ps1"
```

### 2. Telegram Bot Oluşturun

1. Telegram'da [@BotFather](https://t.me/BotFather) ile konuşun
2. `/newbot` komutu ile yeni bot oluşturun
3. Bot Token'ı kaydedin
4. [@userinfobot](https://t.me/userinfobot) ile Chat ID'nizi öğrenin

### 3. Script'i Yapılandırın

Script içindeki bu değerleri düzenleyin:

```powershell
$Config = @{
    # Telegram Ayarları
    TelegramBotToken    = "YOUR_BOT_TOKEN_HERE"    # Bot token'ınız
    TelegramChatID      = "YOUR_CHAT_ID_HERE"      # Chat ID'niz
    
    # Güvenlik Eşikleri
    FailedLoginThreshold    = 5      # Brute-force uyarı eşiği
    AutoBlockThreshold      = 10     # Otomatik engelleme eşiği
    AutoBlockDurationDays   = 30     # Engel süresi (gün)
    RateLimitPerMinute      = 20     # Dakika başına max deneme
    
    # Whitelist (Güvenli IP'ler)
    WhitelistIPs = @(
        "192.168.1.0/24",    # Yerel ağ
        "10.0.0.0/8",        # Özel ağ
        "YOUR_OFFICE_IP"     # Ofis IP'niz
    )
}
```

### 4. Kurulumu Başlatın

```powershell
# Script'i yükleyin
. C:\RDP-Security-Logs\RDP-Security-Intelligence.ps1

# Telegram bağlantısını test edin
Test-TelegramConnection

# Servisi kurun (7/24 çalışır)
Install-MonitoringScheduledTasks
```

---

## 📖 Kullanım

### Durum Komutları

```powershell
Get-MonitoringServiceStatus    # Servis durumu
Get-QuickSecurityStatus        # Hızlı güvenlik özeti
Get-RDPConnections             # Son 24 saat bağlantılar
Get-ActiveRDPSessions          # Aktif oturumlar
```

### Rapor Komutları

```powershell
New-DailyReport                # Günlük HTML rapor oluştur
New-WeeklyReport               # Haftalık HTML rapor oluştur
Show-TargetedUsernames         # Hedeflenen kullanıcı adları
```

### Whitelist Yönetimi

```powershell
Get-WhitelistIPs                        # Whitelist'i görüntüle
Add-WhitelistIP -IPAddress "1.2.3.4"    # IP ekle
Add-WhitelistIP -IPAddress "10.0.0.0/8" # CIDR ekle
Remove-WhitelistIP -IPAddress "1.2.3.4" # IP çıkar
```

### IP Engelleme

```powershell
Get-BlockedIPs                          # Engelli IP'leri gör
Block-IPAddress -IPAddress "1.2.3.4"    # Manuel engelle
Unblock-IPAddress -IPAddress "1.2.3.4"  # Engeli kaldır
Clear-ExpiredBlocks                     # Süresi dolmuş engelleri temizle
```

---

## ⏰ Scheduled Tasks

Kurulum sonrası otomatik oluşturulan görevler:

| Task | Çalışma Zamanı | Açıklama |
|------|---------------|----------|
| RDP Security Monitoring Service | 7/24 | Ana izleme servisi |
| RDP Security Daily Report | Her gün 23:55 | Günlük rapor |
| RDP Security Weekly Report | Her Pazartesi 00:05 | Haftalık rapor |
| RDP Security Log Cleanup | Her Pazar 03:00 | Eski log temizliği |

---

## 📱 Telegram Bildirimleri

Aşağıdaki durumlarda Telegram bildirimi alırsınız:

| Durum | Severity | Açıklama |
|-------|----------|----------|
| Başarılı RDP Girişi | INFO | Yeni bağlantı bildirimi |
| Başarısız Deneme | WARNING | Hatalı giriş denemesi |
| Brute-Force Tespit | CRITICAL | Çoklu başarısız deneme |
| Rate Limit Aşıldı | CRITICAL | Dakika limiti aşıldı |
| Şüpheli Ülke | CRITICAL | Tehlikeli bölgeden bağlantı |
| Şüpheli Process | CRITICAL | Tehlikeli araç tespit edildi |
| IP Engellendi | CRITICAL | Otomatik engelleme yapıldı |

---

## 📁 Dosya Yapısı

```
C:\RDP-Security-Logs\
├── RDP-Security-Intelligence.ps1    # Ana script
├── Connections\                      # Bağlantı logları
│   └── connections_YYYY-MM-DD.json
├── Sessions\                         # Oturum logları
│   └── sessions_YYYY-MM-DD.json
├── Activity\                         # Aktivite logları
│   └── activity_YYYY-MM-DD.json
├── Alerts\                           # Alarm logları
│   └── alerts_YYYY-MM-DD.json
├── Reports\                          # HTML raporlar
│   ├── daily_report_YYYY-MM-DD.html
│   └── weekly_report_YYYY-MM-DD.html
└── BlockedIPs\                       # Engellenen IP'ler
    └── blocked_ips.json
```

---

## 🔧 Yapılandırma Seçenekleri

| Parametre | Varsayılan | Açıklama |
|-----------|------------|----------|
| `FailedLoginThreshold` | 5 | Brute-force uyarı için min. başarısız deneme |
| `AutoBlockThreshold` | 10 | Otomatik engelleme için min. deneme |
| `AutoBlockDurationDays` | 30 | IP engel süresi (gün) |
| `RateLimitPerMinute` | 20 | Dakika başına max. deneme |
| `WhitelistEnabled` | true | Whitelist aktif/pasif |
| `LogRetentionDays` | 90 | Log saklama süresi (gün) |
| `SuspiciousCountries` | CN,RU,KP,IR | Tehlikeli ülke kodları |

---

## ❓ SSS

**S: IPBan ile birlikte kullanabilir miyim?**
C: Evet! IPBan engelleme yapar, bu script izleme ve raporlama sağlar. Birbirini tamamlar.

**S: Telegram bildirimleri çok mu sık geliyor?**
C: Whitelist'e kendi IP'lerinizi ekleyin. Böylece sadece dış tehditler için bildirim alırsınız.

**S: Otomatik engellemeyi kapatabilir miyim?**
C: Evet, `$Config.EnableAutoBlock = $false` yapın.

**S: GeoIP sorguları ücretli mi?**
C: Hayır, ücretsiz DB-IP API kullanılıyor.

---

## 📝 Changelog

### v3.0.0 (2024-12)
- ✨ Otomatik IP engelleme (Windows Firewall)
- ✨ Whitelist desteği (CIDR notation)
- ✨ Rate limiting
- ✨ Şüpheli process tespiti
- ✨ Hedeflenen kullanıcı adı analizi
- ✨ Haftalık HTML raporlar
- ✨ Modern dark tema rapor tasarımı
- ✨ IPBan log okuma desteği
- 🔧 Performans optimizasyonları

### v2.0.0
- İlk public release
- Temel izleme ve raporlama
- Telegram entegrasyonu
- GeoIP desteği

---

## 🤝 Katkıda Bulunun

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

---

## 📄 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 👤 Yazar

**Furkan Dincer**

- GitHub: [@furkandncer](https://github.com/furkandncer)
- LinkedIn: [Furkan Dincer](https://linkedin.com/in/furkandncer)

---

## ⭐ Destek

Bu proje işinize yaradıysa ⭐ vermeyi unutmayın!

---

<p align="center">
  <b>🛡️ Sunucunuzu Koruyun, Güvende Kalın! 🛡️</b>
</p>
