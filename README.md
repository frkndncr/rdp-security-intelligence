# 🛡️ RDP Security Intelligence System v3.0

Windows sunucular için kapsamlı RDP güvenlik izleme ve koruma sistemi. Brute-force saldırılarını tespit eder, otomatik IP engeller, Telegram bildirimi gönderir ve detaylı raporlar oluşturur.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Windows Server](https://img.shields.io/badge/Windows%20Server-2012%20R2+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-3.0.0-red.svg)

---

## 🆕 V3.0 Yenilikler

| Özellik | Açıklama |
|---------|----------|
| 🚫 **Otomatik IP Engelleme** | Brute-force saldırganlarını Windows Firewall'a otomatik ekler |
| ✅ **Whitelist Desteği** | Güvenli IP'lerden alert gelmez (CIDR desteği) |
| ⏱️ **Rate Limiting** | Dakikada max deneme kontrolü |
| 🔍 **Şüpheli Process Tespiti** | mimikatz, psexec, procdump vs. algılama |
| 👤 **Kullanıcı Adı Analizi** | Hangi hesaplar hedefleniyor |
| 📊 **Haftalık Rapor** | 7 günlük trend analizi |
| 🎨 **Modern HTML Raporlar** | Gradient tasarım, grafikler, responsive |

---

## ✨ Tüm Özellikler

### 🔒 Güvenlik
- 7/24 RDP bağlantı izleme
- Brute-force saldırı tespiti
- Otomatik IP engelleme (Firewall)
- Şüpheli ülke uyarısı (CN, RU, KP, IR)
- Şüpheli process tespiti
- Rate limiting

### 📍 İstihbarat
- GeoIP konum tespiti (ülke, şehir, ISP)
- Saldırgan IP analizi
- Hedeflenen kullanıcı adı analizi
- Ülke bazlı istatistikler

### 📱 Bildirimler
- Telegram anlık alertler
- Başarılı/başarısız giriş bildirimi
- Brute-force alarm
- IP engellendiğinde bildirim
- Şüpheli process uyarısı

### 📊 Raporlama
- Günlük HTML rapor (otomatik 23:55)
- Haftalık HTML rapor (Pazartesi 00:05)
- Modern gradient tasarım
- Saatlik/günlük dağılım grafikleri
- En çok saldıran IP listesi

---

## 🚀 Hızlı Kurulum

### 1. Telegram Bot Oluştur
```
1. @BotFather'a git
2. /newbot komutu
3. Bot adı ve username gir
4. Token'ı kaydet
5. @userinfobot'tan Chat ID al
```

### 2. Script'i İndir ve Yapılandır
```powershell
# Token'ları düzenle
$Config = @{
    TelegramBotToken = "YOUR_BOT_TOKEN_HERE"
    TelegramChatID   = "YOUR_CHAT_ID_HERE"
}
```

### 3. Kurulumu Başlat
```powershell
# PowerShell Admin olarak çalıştır
. .\RDP-Security-Intelligence.ps1

# Telegram bağlantısını test et
Test-TelegramConnection

# Servisi kur
Install-MonitoringScheduledTasks
```

### 4. Whitelist Ayarla (Önemli!)
```powershell
# Kendi IP'lerini ekle (alert gelmesin)
Add-WhitelistIP -IPAddress "YOUR_PUBLIC_IP"

# Whitelist'i kontrol et
Get-WhitelistIPs
```

---

## 📋 Komutlar

### Durum Kontrol
```powershell
Get-MonitoringServiceStatus     # Servis durumu
Get-QuickSecurityStatus         # Hızlı özet
Get-RDPConnections              # Son 24 saat bağlantıları
```

### Raporlar
```powershell
New-DailyReport                 # Günlük HTML rapor
New-WeeklyReport                # Haftalık HTML rapor
Show-TargetedUsernames          # Hedeflenen kullanıcı adları
```

### Whitelist Yönetimi
```powershell
Get-WhitelistIPs                      # Whitelist listele
Add-WhitelistIP -IPAddress "x.x.x.x"  # IP ekle
Remove-WhitelistIP -IPAddress "x.x.x.x"  # IP çıkar
```

### IP Engelleme
```powershell
Get-BlockedIPs                        # Engelli IP'leri göster
Block-IPAddress -IPAddress "x.x.x.x"  # Manuel IP engelle
Unblock-IPAddress -IPAddress "x.x.x.x"  # Engeli kaldır
Clear-ExpiredBlocks                   # Süresi dolanları temizle
```

---

## ⚙️ Yapılandırma

Script içindeki `$Config` bölümünden ayarlanabilir:

```powershell
$Config = @{
    # Güvenlik Eşikleri
    FailedLoginThreshold    = 5       # Kaç denemede brute-force alarmı
    AutoBlockThreshold      = 10      # Kaç denemede otomatik engel
    AutoBlockDurationDays   = 30      # Engel süresi (gün)
    RateLimitPerMinute      = 20      # Dakikada max deneme
    
    # Şüpheli Ülkeler
    SuspiciousCountries     = @("CN", "RU", "KP", "IR")
    
    # Whitelist (varsayılan)
    WhitelistIPs            = @("192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12")
    
    # Şüpheli Process'ler
    SuspiciousProcesses     = @("mimikatz", "psexec", "procdump", "lazagne")
    
    # Log Saklama
    LogRetentionDays        = 90
}
```

---

## 📁 Dosya Yapısı

```
C:\RDP-Security-Logs\
├── RDP-Security-Intelligence.ps1   # Ana script
├── Connections\                     # Bağlantı logları
├── Sessions\                        # Oturum logları
├── Activity\                        # Aktivite logları
├── Alerts\                          # Alarm logları
├── Reports\                         # HTML raporlar
└── BlockedIPs\                      # Engelli IP kayıtları
```

---

## 🔧 Scheduled Tasks

| Task | Zaman | Açıklama |
|------|-------|----------|
| RDP Security Monitoring Service | 7/24 | Ana izleme servisi |
| RDP Security Daily Report | 23:55 | Günlük rapor |
| RDP Security Weekly Report | Pazartesi 00:05 | Haftalık rapor |
| RDP Security Log Cleanup | Pazar 03:00 | Eski log temizliği |

---

## 📱 Telegram Bildirimleri

Şu durumlarda Telegram'a mesaj gelir:
- ✅ Başarılı RDP girişi (whitelist dışı)
- ❌ Başarısız RDP denemesi
- 🚨 Brute-force saldırısı
- 🌍 Şüpheli ülkeden bağlantı
- ⏱️ Rate limit aşıldığında
- 🚫 IP otomatik engellendiğinde
- ⚠️ Şüpheli process tespit edildiğinde

---

## 📸 Ekran Görüntüleri
<img width="723" height="583" alt="resim" src="https://github.com/user-attachments/assets/ab068cb4-8cfc-42df-b510-10bb15af7d8f" />

### Günlük Rapor
- Özet kartlar (başarılı/başarısız/aktif/tehdit)
- En çok saldıran IP'ler tablosu
- Ülke dağılımı grafiği
- Saatlik saldırı yoğunluğu
- Başarılı girişler listesi
- Aktif oturumlar

### Telegram Alert
```
[!!!] RDP Security Alert [!!!]
========================
Server: SERVER_NAME
Time: 2024-12-04 15:30:45
Severity: CRITICAL

Brute Force Saldirisi Tespit Edildi

Coklu basarisiz giris: 119.148.8.66
- IP : 119.148.8.66
- Ulke : Bangladesh
- Deneme : 150
========================
```

---

## ❓ SSS

**S: IPBan ile birlikte kullanabilir miyim?**
C: Evet, çakışmaz. İkisi de bağımsız çalışır.

**S: Kendi IP'mden alert gelmesin nasıl yaparım?**
C: `Add-WhitelistIP -IPAddress "IP_ADRESIN"` komutu ile whitelist'e ekle.

**S: Otomatik engellemeyi kapatabilir miyim?**
C: `$Config.EnableAutoBlock = $false` yaparak kapatabilirsin.

**S: Engel süresi ne kadar?**
C: Varsayılan 30 gün. `$Config.AutoBlockDurationDays` ile değiştirebilirsin.

---

## 📄 Lisans

MIT License - Özgürce kullanabilir ve değiştirebilirsiniz.

---

## 👤 Geliştirici

**Furkan Dincer**
- GitHub: [@frkndncr](https://github.com/frkndncr)
- LinkedIn: [/in/furkandncer](https://linkedin.com/in/furkan-dincer)
- İnstagram: [@f3rrkan](https://instagram.com/f3rrkan)

---

## ⭐ Destek

Projeyi beğendiyseniz ⭐ vermeyi unutmayın!

---

## 📝 Changelog

### v3.0.0 (2024-12-04)
- ✨ Otomatik IP engelleme (Windows Firewall)
- ✨ Whitelist desteği (CIDR notation)
- ✨ Rate limiting
- ✨ Şüpheli process tespiti
- ✨ Hedeflenen kullanıcı adı analizi
- ✨ Haftalık rapor
- 🎨 Modern HTML rapor tasarımı
- 🐛 Çeşitli hata düzeltmeleri

### v2.0.0
- İlk public release
- Temel monitoring özellikleri
- Telegram entegrasyonu
- Günlük raporlama
