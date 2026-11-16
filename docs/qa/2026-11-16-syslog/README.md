# Syslog / SIEM QA — 16 Kasım 2026

Tarihsel ilk uygulama QA kaydıdır. Sonraki QA'da dört kusur düzeltildi;
güncel sonuçlar için [tekrar QA raporuna](../2026-11-16-syslog-repeat/README.md) bakın.

[Kurulum ve davranış](../../SYSLOG.md). Değişiklikler bu turda commit/push edilmedi.

- [Tam test çıktısı](tests.txt): **206/206 OK**, 15 yeni syslog testi.
- [UBI 9 x86_64 syslog testleri](linux-tests.txt): **15/15 OK**. Host data/anahtarı/Docker soketi mount edilmedi.
- [Browser ölçümleri](browser-checks.json), [gerçek yerel UDP alıcı özeti](receiver-checks.json).
- [UI fixture sunucusu](serve_fixture.py): kendi geçici DB/anahtarı, sentetik admin/Viewer, gerçek loopback UDP receiver.
  Normal lifespan/worker/scheduler/Strix/provider yok; yalnız syslog dispatcher çalışır.

| Görünüm | 1366×768 | 1920×1080 |
|---|---|---|
| Varsayılan kapalı form | [Ekran](disabled-1366.jpg) | [Ekran](disabled-1920.jpg) |
| Etkin UDP ve handoff sayacı | [Ekran](enabled-status-1366.jpg) | [Ekran](enabled-status-1920.jpg) |
| Hata / pending / retry | [Ekran](retrying-1366.jpg) | [Ekran](retrying-1920.jpg) |
| Viewer Settings | [Ekran](viewer-settings-1366.jpg) | [Ekran](viewer-settings-1920.jpg) |

Ek: [TLS alanları](tls-expanded-1366.jpg), [UDP probe sonucu](udp-test-1920.jpg).
Sayfalar kaydırılabilir; uzun formun tamamının tek viewport'a sığdığı iddia edilmez.

Browser'da form değerleriyle gerçek loopback alıcısına probe geldi; etkinleştirme audit kaydı da ayrıca geldi.
Toplam iki farklı `event_id`; içerikler `skynet.audit.v1` olarak parse edildi. Sonra kapalı localhost TCP portuyla
test hatası ve iki pending retry görünür oldu. Forwarding kapatılınca bu iki kayıt superseded oldu.
Viewer syslog alanlarını göremez. Ölçülen sayfalarda yatay taşma/konsol hatası yok; örnek screenshot'lar incelendi.

Unit/API testleri: admin yetkisi/CSRF mevcut merkez politikayla korunuyor; konfigürasyon doğrulama; probe'un
forwarding'i etkinleştirmemesi; eski kayıtların toplu gönderilmemesi; audit/outbox transaction atomikliği;
restart sonrası aynı event_id ile retry; hedef değişimi ve uçuşta config değişimi; sonradan öğrenilen sırların
maskelenmesi; Unicode/newline güvenliği; okunamayan maskelemede hiçbir gönderim olmaması; 10.000 pending sınırı;
gerçek UDP/TCP octet counting; TLS CA/hostname ve yanlış hostname reddi; gerçek mTLS client sertifikası.

Gerçek SIEM adresi verilmedi; dış SIEM'e paket gönderilmedi ve ingestion doğrulanmış sayılmadı.
Yerel ana uygulama migration 8 ile güncellendi; forwarding kapalı/collector boş. Migration öncesi tutarlı
yedek ve tarama/zamanlama boşluğu doğrulandı; yeni pentest başlatılmadı. Gerçek RHEL host egress/firewall/SELinux
ve kurum SIEM parser/indexer kabulü henüz yapılmadı.
