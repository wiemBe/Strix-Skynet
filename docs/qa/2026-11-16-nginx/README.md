# Aynı sunucuda Nginx QA — 16 Kasım 2026

Kurulum: [NGINX.md](../../NGINX.md). Uygulama ve Nginx aynı UBI 9 x86_64 QA konteynerinde çalıştı.
Host portu yayınlanmadı; host DB/anahtarı veya Docker soketi mount edilmedi. Yalnız `skynet/` ve `scripts/`
salt okunur mount edildi. Uygulamanın normal lifespan'ı kapalı; worker/scheduler/Strix/provider çağrısı yok.
Test hedefi kaydı yalnız geçici veritabanında oluşturuldu, tarama başlatılmadı.

- [191 testin çıktısı](tests.txt): 8 yeni deployment testi, mevcut 183 test korunuyor.
- [Gerçek Nginx HTTP/HTTPS sonuçları](integration.json), [nginx -t çıktısı](integration.log).
- [HTTP dry-run örneği](http-example.conf), [HTTPS dry-run örneği](https-example.conf).
  Bunlardaki `10.90.10.10` gerçek kurulum adresi değildir.
- [UBI imaj build çıktısı](build.txt): mevcut `skynet-rhel9-qa:local` üzerine resmi UBI repo Nginx/OpenSSL paketleri.
  Paketli `curl-minimal` korundu; `--allowerasing` kullanılmadı.
- Betik: [qa_nginx.py](../../../scripts/qa_nginx.py). Yalnız ayrı bir QA konteynerinde `--disposable-qa` ile çalışır.

Tekrar çalıştırma (repo kökünde; mevcut RHEL QA imajı gerekir):

```sh
docker build --platform linux/amd64 -t skynet-nginx-qa:local - < deploy/rhel/Containerfile.nginx-qa
docker run --rm --platform linux/amd64 \
  --mount "type=bind,source=$PWD/skynet,target=/qa/skynet,readonly" \
  --mount "type=bind,source=$PWD/scripts,target=/qa/scripts,readonly" \
  skynet-nginx-qa:local /opt/skynet/.venv/bin/python /qa/scripts/qa_nginx.py --disposable-qa
```

HTTP ve HTTPS için doğrulandı:

- Nginx konfigürasyonu geçerli; login, oturum, statik varlıklar ve API erişimi çalışıyor.
- HttpOnly/SameSite korunuyor; TLS modunda Secure set ediliyor.
- CSRF başlığı olmayan mutasyon reddediliyor; geçerli başlıkla yalnız test hedefi oluşturulabiliyor.
- İzin dışı kaynak 403; gerçek istemci IP'si audit'e ulaşıyor. İstemcinin sahte X-Forwarded-For değeri yok sayılıyor.
- Güvenilen peer adresi dışından backend'e gelen spoofed header da kabul edilmiyor.
- Backend'e konteyner ağ IP'sinin 8787 portundan bağlanılamıyor; yalnız loopback dinliyor.
- Access log test query değerini içermiyor.
- TLS sertifikası QA'ya özel geçici CA/cert olarak client context'e açıkça verildi; IP SAN ve trust doğrulandı,
  TLS doğrulaması kapatılmadı. Kalıcı sunucu/istemci güven deposuna sertifika eklenmedi.
- HTTP→HTTPS yönlendirmesi sabit sunucu IP'sine gidiyor; Host spoof hedefi değiştirmiyor.
- Üretim kurucusu dry-run'da sistem değiştirmiyor; geçersiz Nginx testinde önceki managed dosya geri yükleniyor.

Gerçek RHEL sunucusu bu turda verilmedi. systemd enable/reload, SELinux enforcing boolean ve firewalld rich
rule'larının gerçek host üzerinde uygulanması; ağ/routing ve uzak istemci tarayıcısı kabulü bekliyor.
Nginx'in o sunucuya kurulduğu veya dışarıdan erişilebilir olduğu raporlanamaz. Repo değişiklikleri commit/push edilmedi.
