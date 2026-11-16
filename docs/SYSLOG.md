# SIEM / Syslog entegrasyonu

Settings → **SIEM / Syslog** bölümünü yalnız Admin yönetir. Uygulamanın güvenlik audit olayları,
RFC 5424 başlığı ve JSON mesaj gövdesiyle bir syslog alıcısına gönderilir. Varsayılan kapalıdır;
sunucu/port girilmeden veya yönetici etkinleştirmeden dışarı log gönderilmez.

## Kurulum

1. SIEM'de RFC 5424 alan bir giriş tanımlayın. TLS önerilir; varsayılan port 6514'tür.
2. Collector address, port, transport ve facility seçin. UDP/TCP için alışılmış port 514'tür;
   alıcınız farklı port kullanıyorsa onu girin. TCP ve TLS **octet-counted** framing kullanır.
3. Source hostname ile bu kaynağa bir ASCII ad verin. Uygulama etiketi `skynet`'tir.
4. TLS'te varsayılan sistem güven deposu kullanılır. Gerekirse CA bundle path girin. Collector'a IP ile
   bağlanıp sertifikayı DNS adıyla doğrulamak için TLS server name kullanılabilir.
5. mTLS gerekiyorsa client certificate/key dosya yollarının ikisini de girin. Dosyalar uygulama sunucusunda
   bulunmalı ve Skynet servis hesabınca okunabilmelidir; içerikleri GUI'ye yüklenmez veya API'den döndürülmez.
   Özel anahtar şifresiz PEM olmalıdır; uygulama interaktif anahtar parolası istemez. Anahtarı ayrı, korumalı
   bir dizinde tutun. Bu TLS anahtarı, Skynet'in mevcut Vault şifreleme anahtarından ayrıdır.
6. **Send test event** formdaki hedefe sentetik bir probe gönderir; ayarı kaydetmez/etkinleştirmez.
   Alıcının gerçekten gördüğünü SIEM'den kontrol edin. Sonra checkbox'ı açıp **Save syslog settings** kullanın.
   Sonuç test edilen transport/adres/port'a aittir; form değişince eski sonuç temizlenir.
   Geçersiz girişte de test tamamlanır, hata gösterilir ve düğme tekrar kullanılabilir.

Sertifika zinciri ve hostname doğrulaması her TLS bağlantısında açık kalır; doğrulamayı kapatan veya
TLS başarısız olduğunda UDP/TCP'ye düşen bir seçenek yoktur. UDP ve düz TCP şifreleme sağlamaz.

RHEL'de örnek korumalı dosya yerleşimi:

```sh
sudo install -d -o skynet -g skynet -m 0700 /var/lib/skynet-tls
sudo install -o skynet -g skynet -m 0600 /safe/import/client.key /var/lib/skynet-tls/client.key
sudo install -o skynet -g skynet -m 0644 /safe/import/client.crt /var/lib/skynet-tls/client.crt
sudo install -o skynet -g skynet -m 0644 /safe/import/siem-ca.pem /var/lib/skynet-tls/siem-ca.pem
```

Skynet servisi bu dosyaları yalnız okur. Sunucudan seçilen collector/port'a egress erişimi gerekir;
entegrasyon firewalld veya SELinux'ı kapatmaz, yeni ingress portu açmaz. RHEL systemd biriminin tek uygulama
süreci kuralı devam eder. TLS dosya yolları macOS'ta da o makinenin mutlak yolları olmalıdır.

## Hangi olaylar gider?

Mevcut `audit_log` kaynağı kullanılır: başarılı/başarısız giriş, çıkış, reddedilen değiştirici API işlemi,
kullanıcı/rol/parola yönetimi, ayar/profil değişikliği, manuel/CI/zamanlayıcı tarama başlatma, durdurma/sürdürme,
bulgu durumu/not/etiket/ilişkilendirme/doğrulama talebi, rapor görüntüleme ve syslog yapılandırma/test aksiyonları.
Başarısız girişte mevcut olmayan kullanıcı adı audit politikasına göre `unknown user` olur.

Bu sürüm **audit olaylarını** dışa aktarır. Strix stdout/stderr, ajan prompt'u, tool sonucu, ham HTTP kanıtı,
rapor içeriği ve genel Python traceback'leri aktarılmaz. Otomatik tarama bitişi, tek tek yeni bulgu ve bütün
runtime hataları için yeni olay kaynağı eklendiği iddia edilmez. Mevcut audit kaydı hangi olayı üretiyorsa o gider.

JSON `schema=skynet.audit.v1` alanını taşır. Alanlar:

| Alan | Anlam |
|---|---|
| `event_id` | Kalıcı instance UUID + yerel audit id; tekrar denemelerde değişmez |
| `id`, `at` | Orijinal audit kimliği ve UTC kaynak zamanı |
| `actor`, `actor_id`, `actor_role` | İşlemi yapan hesap veya sistem kaynağı |
| `action` | Kararlı aksiyon adı, ör. `auth.login_failed`, `scan.start` |
| `object_type`, `object_id` | İlgili Skynet nesnesi |
| `summary` | Kısa, maskelenmiş literal metin; JSON'a benzese de metin olarak korunur |
| `method`, `path`, `status`, `ip` | İstek metodu, yolu, HTTP sonucu ve istemci IP'si |

HTTP 5xx syslog Error (3), 4xx Warning (4), diğer olaylar Informational (6) önceliği alır.
Bu seviye pentest bulgusunun önem derecesi değildir. Facility varsayılanı local0 (16), seçim aralığı 0–23.
JSON ASCII kaçışlarıyla Unicode'u korur; satır sonları escape edilir ve yeni syslog kaydı enjekte edemez.

## Kuyruk ve teslim anlamı

- Migration 8 konfigürasyon ve `syslog_outbox` tablolarını ekler. Var olan SQLite backup mekanizması önce
  tutarlı 0600 yedek alır. Mevcut şifreleme anahtarı değiştirilmez; instance UUID bir kaynak kimliğidir.
- Etkin ayar varken audit INSERT trigger'ı aynı SQLite transaction'ında outbox'a kayıt koyar. İstek işleyicisi
  network gönderimi yapmaz. Ayrı dispatcher en geç normal 1 saniyelik idle poll'da yeni kayıtları ele alır.
- Restart'ta bekleyen işler korunur. Socket işlemlerinde 3 saniye timeout vardır; DNS çözümlemesi OS resolver
  davranışını kullanır. Hatalar, girişim tamamlandıktan sonra 2 saniyeden başlayıp 300 saniyeye kadar artan
  aralıkla yeniden denenir; yavaş bir girişim bu bekleme aralığını tüketmez.
- Pending sınırı 10.000'dir. Dolduğunda yeni olay `overflow` olarak görünür; yerel audit kaydı korunur.
  Overflow kayıtları kendiliğinden daha sonra yeniden kuyruğa alınmaz. Bu sınır tüm DB boyutunu sınırlamaz;
  audit/outbox metadata'sı için otomatik retention/purge eklenmedi.
- Eski audit geçmişi ilk etkinleştirmede topluca gönderilmez. Kaydedilen ayar gerçekten değişirse bekleyen
  işler `superseded` olur; eski collector'ın kuyruğu yeni collector'a gönderilmez. Disable da bunu yapar.
  Aynı ayarı tekrar kaydetmek kuyruğu geçersiz kılmaz. Zaten uçuşta olan bir gönderim tamamlanabilir;
  o girişimin/handoff'un metadata'sı korunur. Gönderilmiş byte'lar geri alınamaz.
- Sayaçlar bütün konfigürasyonların toplamıdır; son handoff mevcut konfigürasyona aittir. Hata uyarısı mevcut
  konfigürasyonda hâlâ pending olan en son başarısız girişimi gösterir; başka bir olayın başarısı onu gizlemez.
- **Handed to transport, SIEM ingestion onayı değildir.** UDP'de datagramın sokete verilmesinden öte alım
  garantisi yoktur. TCP/TLS send başarısı da parser/indexer kabulü değildir. Bağlantı kopuşu veya işlem
  çökmesi gibi belirsiz durumlarda tekrarlar oluşabilir. SIEM'de `event_id` ile deduplicate edin.
- Test probe'u doğrudan gönderilir ve outbox sayacına dahil değildir. Test aksiyonunun normal audit kaydı,
  o sırada forwarding etkinse diğer audit kayıtları gibi ayrıca kuyruklanır.

Audit kaydı yazılırken mevcut maskeleme uygulanır. Gönderimden hemen önce güncel Vault değerleri ve saklanan
eski tarama maskeleme verileri tekrar uygulanır. Outbox payload kopyası tutmaz, audit kaydına referans verir.
Maskeleme verisi okunamıyorsa olay maskesiz gönderilmez; pending kalır ve hata görünür. Hata alanında ham socket/TLS
exception metni saklanmaz. Önceden bilinmeyen sırların mutlak olarak yakalanacağı veya SIEM'den geçmiş verinin
geri alınacağı iddia edilmez. Collector IP'si, kaynak kimliği, aktör/IP metadata'sı SIEM yöneticisinin yetkisindeki veridir.

## Doğrulama

[Son QA ve dört düzeltme](qa/2026-11-16-syslog-repeat/README.md): macOS'ta 212/212 test;
UBI 9 x86_64'te 21/21 syslog testi. [İlk uygulama QA'sı](qa/2026-11-16-syslog/README.md) tarihsel kayıttır.
Gerçek localhost UDP/TCP/TLS/mTLS alıcıları, yanlış hostname reddi, durable retry/restart, atomik insert,
maskeleme, overflow, konfigürasyon değiştirme yarışı ve admin yetkisi sınandı. Güvenilmeyen CA ve şifreli client
anahtarı reddi de test edildi. Ayrı süreçler arasında aynı event_id ile gerçek TCP teslimi doğrulandı.
1366×768 / 1920×1080 görsel QA yapıldı.
Gerçek kurum SIEM'i veya RHEL host egress/SELinux kabulü bu kontrollerin yerine geçmez; collector bilgisi verilmedi.

Biçim/taşıma dayanakları: [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html),
[TLS taşıması RFC 5425](https://www.rfc-editor.org/rfc/rfc5425.html),
[TCP octet counting RFC 6587](https://www.rfc-editor.org/rfc/rfc6587.html).
