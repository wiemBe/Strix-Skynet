# RHEL UBI 9 yeniden test ve düzeltme kaydı

16 Kasım 2026 · Europe/Istanbul · kaynak `09ad607` · branch `fix/rhel-qa`.

Repo Fedora 44 çalışma alanına klonlandı; testler rootless Podman içinde resmi
Red Hat UBI 9 x86_64 kullanıcı alanında çalıştırıldı. İmaj, repodaki
`deploy/rhel/Containerfile.qa` digest'iyle oluşturuldu. UBI sürümü 9.9,
Python 3.12.15, glibc 2.34, Nginx 1.20.1, systemd 252.
Konteyner Fedora host'un çekirdeğini paylaşır; bu çalışma RHEL sanal makinesi veya fiziksel sunucu kabulü değildir.

## Düzeltilen kusurlar

| Kusur | Önce | Sonra |
| --- | --- | --- |
| Doctor başarısız yetenek sonucu | `sqlite_json_check=False` için `ok=true` | Başarısız kontrol ve genel sonuç `false` |
| Anahtar eksik, yalnız mesaj/not şifreleri var | Yeni anahtar üretiliyor; eski şifreli kayıtlar çözülemiyor | `agent_messages.content_enc` ve `analyst_note_revisions.body_enc` de başlangıcı durduruyor; mevcut anahtarın geri yüklenmesi isteniyor |
| Veri yolunda `#` veya `?` var | SQLite URI yanlış DB'yi kontrol edebiliyor; şifreli veriye rağmen yeni anahtar üretiliyor | Dosya yolu `Path.as_uri()` ile kodlanıyor; mevcut DB salt okunur inceleniyor |
| Podman üzerinde Nginx QA | Yalnız `/.dockerenv` tanındığı için test başlamıyor | `/run/.containerenv` de tanınıyor; açık `--disposable-qa` koşulu korunuyor |

Yeni regresyonlar düzeltmelerden önce UBI 9'da başarısız oldu:
[doctor](doctor-regression-before.txt), [anahtar ve dosya yolu](key-regressions-before.txt),
[Podman Nginx](nginx-before.txt). Altı şifreli veri tablosu için anahtar/DB koruması kontrol ediliyor.

## Sonuçlar

- [Başlangıç: 191 test](tests-before.txt); [son: 193 test, OK](tests-after.txt).
  Native Strix koordinatörü, session ve SDK köprüsü testleri dahil; atlanan test yok.
- [Gerçek HTTP/HTTPS Nginx kontrolleri](nginx-after.txt): oturum, CSRF, kaynak CIDR,
  statik dosyalar, gerçek istemci IP'si, spoofed forwarded header reddi, kapalı backend,
  query içermeyen access log, Secure cookie, IP SAN/CA doğrulaması ve HTTPS yönlendirmesi geçti.
  HTTP kaydındaki TLS/Secure alanlarının `false` olması beklenir; bu kontroller HTTPS modunda `true`.
- [Uygulama yaşam döngüsü](service-lifecycle.json): gerçek `python -m skynet` başlangıcıyla
  giriş, hedef/profil/kampanya/devre dışı zamanlama oluşturma ve yeniden başlatma sonrası doğrulama geçti.
  Anahtar ve şifreli kayıtlar korundu; SQLite integrity `ok`; şema 7.
  Doctor'ın Docker hariç tüm kontrolleri geçti (`docker_checked=false`).
- RHEL systemd ile `systemd-analyze verify /opt/skynet/deploy/rhel/skynet.service` çıkış kodu 0.
  Bu birim doğrulamasıdır; systemd ile servisi başlatma testi değildir.
- İki venv'de `pip check`, `compileall`, shell ve üç frontend JS dosyası için sözdizimi kontrolleri geçti.
  [Ortam](environment.txt), [ek kontroller](verification.txt).

## Tekrar çalıştırma

Repo kökünde; host veri dizinlerini, anahtarlarını veya Docker soketini paylaşmayın:

```sh
podman build --platform linux/amd64 -f deploy/rhel/Containerfile.qa -t localhost/skynet-rhel9-qa:local .
podman run --rm localhost/skynet-rhel9-qa:local
podman build --platform linux/amd64 -f deploy/rhel/Containerfile.nginx-qa -t localhost/skynet-nginx-qa:local .
podman run --rm --workdir /opt/skynet localhost/skynet-nginx-qa:local \
  .venv/bin/python scripts/qa_nginx.py --disposable-qa
```

Yaşam döngüsü kontrolü, bu raporla saklanan [betikle](service_lifecycle_check.py) tekrar edilebilir:

```sh
podman run -d --name skynet-service-qa localhost/skynet-rhel9-qa:local sleep infinity
podman cp docs/qa/2026-11-16-rhel-codex/service_lifecycle_check.py skynet-service-qa:/tmp/service_lifecycle_check.py
podman exec skynet-service-qa .venv/bin/python /tmp/service_lifecycle_check.py --disposable-qa
podman rm -f skynet-service-qa
```

## Gerçek sunucuda kalan kabul

RHEL 9.4+ x86_64 sunucuda installer ve systemd boot/stop davranışı, SELinux enforcing,
firewalld/routing, uzaktaki istemci erişimi, Docker Engine soket izinleri ve gerçek izinli sandbox
taraması ayrıca doğrulanmalı. FIPS modu test edilmedi. Podman bu çalışmada QA konteynerlerini
çalıştırdı; Strix için üretim Docker alternatifi olarak doğrulanmadı.
Hiçbir harici hedef taranmadı, sağlayıcıya LLM isteği yapılmadı ve host servisleri değiştirilmedi.
