# Syslog tekrar QA — 16 Kasım 2026

Kapsam: yeni SIEM/Syslog entegrasyonu, audit metni ve ilgili Settings/Viewer ekranları. Bu tur bütün ürünün
her akışını yeniden kabul testi olarak kapsamaz. Mevcut main çalışma ağacı incelendi; özellik kararları kanıt
sayılmadı. Gerçek pentest, LLM çağrısı veya kurum SIEM'ine gönderim yapılmadı.

## Bulunan ve kapatılan kusurlar

| Kusur | Kanıt ve düzeltme |
|---|---|
| Başka olayın başarısı pending hatayı gizliyordu | İki olaydan biri başarısız, diğeri başarılıyken status hatası boş dönüyordu. Artık mevcut generation'ın hâlâ pending olan en son hatası/zamanı gösteriliyor. |
| Audit özeti JSON'a benziyorsa türü değişiyordu | Ortak DB decoder'ı `123`, `null`, `true`, object/list metinlerini JSON değere çeviriyordu. SIEM `summary` tipi bozuluyor, audit feed maskelemesi metin dışı değer alıyordu. Audit ve dispatcher sorgularında ayrı literal alias kullanıldı; kaynak kayıt yeniden yazılmadı. |
| Yavaş girişim retry bekleme süresini tüketiyordu | Zaman 100'de başlayan, 5 saniye süren başarısız ilk girişim 102'ye planlanıyordu; artık 107'ye planlanır. Bekleme tamamlanan girişimden başlar; geçen süre monotonic saatle hesaplanır. |
| Form doğrulama hatasında test görünümü takılı kalıyordu | Boş collector ile hata toast'ı çıksa da `Testing transport…` kalıyordu. Hata sonuç alanına yazılıyor, düğme açılıyor. Sonuç test edilen endpoint'i gösteriyor; alan değişince eski sonuç temizleniyor. |

[Düzeltme öncesi regresyonlar](before-tests.txt): o aşamada 18 testten üçü başarısız.
[Önceki takılı test ekranı](before-stuck-test.jpg). Altı yeni testin tamamı düzeltme öncesi çalıştırılmış gibi
raporlanmamalı: audit API ve iki ek TLS testi sonradan eklendi.

## Otomatik ve gerçek taşıma kontrolleri

- [Tam test çıktısı](tests.txt): **212/212 OK**. Çıktıda bazı test fixture SQLite bağlantıları için Python
  `ResourceWarning` var; test başarısızlığı veya temiz konsol iddiasına dahil edilmedi. Unsafe control-file
  uyarısı ilgili güvenlik testinin beklenen çıktısıdır.
- [Syslog regresyonları](after-siem-tests.txt): **21/21 OK**. Son API testi güçlendirilip literal özetin
  authenticated `GET /api/audit` üzerinden 200/text olarak dönmesi ayrıca doğrulandı.
- [UBI 9 Linux x86_64](linux-tests.txt): **21/21 OK**; `skynet-nginx-qa:local` image'ı, salt okunur kod/test
  mount'ları, gerçek host data/anahtar mount'u yok. Linux koşusundan sonra yalnız audit API testinin çağrısı
  güçlendirildi; uygulama kodu değişmedi, güncel 21 test macOS'ta tekrar geçti.
- Altı yeni regresyon: pending hata görünürlüğü, JSON biçimli özetlerin SIEM'de metin kalması, aynı özetlerin
  audit API'de metin kalması, yavaş gönderim sonrası backoff, güvenilmeyen CA reddi, şifreli client anahtarında
  prompt/network olmadan güvenli hata. Önceki UDP/TCP/TLS/mTLS, hostname, maskeleme, atomik outbox, overflow,
  konfigürasyon yarışı ve admin yetkisi testleri de geçti.
- [Ayrı süreç restart testi](process_restart_check.py), [sonuç](process-restart.json): dinlemeyen localhost TCP
  portuna ilk girişim pending/attempts=1 olarak kalıcı yazıldı. Yeni Python süreci aynı DB'yi açtı; alıcı açıldıktan
  sonra aynı event_id ile tek paket aldı, attempts=2/handoff doğrulandı. Hızlı QA için ikinci süreçte due-time
  kontrolüne 600 saniye ileri test zamanı verildi; gerçek üretim bekleme süresi atlanmış gibi yorumlanmamalı.
- [Tarayıcı fixture alıcısı](receiver-checks.json): gerçek loopback UDP'de 1 probe ve 2 queued audit olayı,
  üçünde de event_id. Sonunda forwarding kapatıldı; fixture server/data/key temizlendi.

Komutlar:

```sh
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m unittest discover -s tests -p test_siem.py
docker run --rm --platform linux/amd64 --env SKYNET_LOAD_DOTENV=0 \
  --mount type=bind,source="$PWD/skynet",target=/qa/skynet,readonly \
  --mount type=bind,source="$PWD/tests",target=/qa/tests,readonly \
  skynet-nginx-qa:local /opt/skynet/.venv/bin/python -m unittest discover -s /qa/tests -p test_siem.py
.venv/bin/python docs/qa/2026-11-16-syslog-repeat/process_restart_check.py
```

## Görsel ve etkileşim QA

1366×768 ve 1920×1080'de validation hatası, gerçek UDP probe sonucu, uzun CA yolu/TLS hatası ve Viewer
hesabı incelendi. [Ölçümler](browser-checks.json): sekiz son durumda yatay taşma yok, validation spinner'ı
takılmıyor, Viewer'da syslog bölümü yok. [Tarayıcı warning/error kaydı](console.json) boş.
Hata ve başarı sonucunun alan değişiminde temizlendiği ayrıca etkileşimle doğrulandı.

| Durum | 1366×768 | 1920×1080 |
|---|---|---|
| Validation hatası sonrası kullanılabilir form | [Ekran](validation-fixed-1366.jpg) | [Ekran](validation-fixed-1920.jpg) |
| Gerçek yerel UDP probe handoff'u | [Ekran](probe-fixed-1366.jpg) | [Ekran](probe-fixed-1920.jpg) |
| Uzun CA yolu ve güvenli TLS hata mesajı | [Ekran](tls-error-1366.jpg) | [Ekran](tls-error-1920.jpg) |
| Viewer hesap ayarları | [Ekran](viewer-1366.jpg) | [Ekran](viewer-1920.jpg) |

## Yerel uygulama ve sınırlar

Gerçek uygulamada readonly kontrol: aktif/queued/stopping tarama 0, enabled schedule 0, syslog disabled,
collector boş, schema 8. Bizim başlattığımız idle servis güncel kodla yeniden açıldı; mevcut anahtar ve oturum
korundu. Yeni migration veya tarama çalıştırılmadı. [Güncel gerçek uygulama](actual-app.jpg) sağdaki tarayıcıda
`http://127.0.0.1:8787/#/settings` üzerinde açık; dispatcher running, forwarding disabled, sayaçlar 0.

Gerçek kurum SIEM parser/indexer ingestion, gerçek RHEL systemd/egress/SELinux ve uzak istemci kabulü
collector/host verilmediği için denenmedi. Transport handoff'u ingestion onayı değildir. Bu tur commit/push yok.
