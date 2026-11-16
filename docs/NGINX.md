# Aynı RHEL sunucusunda Nginx ve IP ile erişim

Nginx ve Skynet **aynı sunucuda** çalışır:

`Tarayıcı → sunucunun LAN IP'si:80/443 → Nginx → 127.0.0.1:8787 → Skynet`

Tarayıcıya yalnız `http://SUNUCU_IP` veya HTTPS kurulduysa `https://SUNUCU_IP` yazılır; uygulama portu
eklenmez. `10.90.10.10` aşağıda **örnektir**; kurucu IP atamaz. Gerçek adres sunucunun arayüzünde zaten
tanımlı olmalıdır. Hedef RHEL 9.4+ x86_64; temel uygulama kurulumu [RHEL.md](RHEL.md).

## HTTP ile kurum içi test kurulumu

Skynet servisinin zaten sağlıklı çalışması gerekir. Kurucu uygulamayı başlatmaz/yeniden başlatmaz;
mevcut kuyruğa, zamanlamalara, DB'ye veya şifreleme anahtarına dokunmaz. Ortam dosyası şu değerlerle
çalışıyor olmalı:

```ini
SKYNET_HOST=127.0.0.1
SKYNET_PORT=8787
SKYNET_COOKIE_SECURE=0
```

Sunucuda gerçek IP, istemcilerin izinli kaynak ağı ve ilgili arayüzün firewalld bölgesini öğrenin:

```sh
ip -4 address
sudo firewall-cmd --get-active-zones
sudo systemctl status skynet
```

HTTP başlıklarını GET ile kontrol etmek için:

```sh
curl --noproxy '*' -sS -D - -o /dev/null http://127.0.0.1:8787/login
```

Önce değişiklik yapmayan planı görüntüleyin. Örnekte istemciler `10.90.10.0/24` ağından, arayüz bölgesi
`internal` olarak varsayılmıştır; bu değerleri gerçek ortama göre değiştirin:

```sh
cd /opt/skynet
.venv/bin/python scripts/install_nginx_rhel.py \
  --ip 10.90.10.10 --allow-cidr 10.90.10.0/24 --zone internal
```

Gerçek sunucuda kurmak için:

```sh
sudo /opt/skynet/.venv/bin/python /opt/skynet/scripts/install_nginx_rhel.py \
  --ip 10.90.10.10 --allow-cidr 10.90.10.0/24 --zone internal --apply
```

Birden fazla istemci ağı için `--allow-cidr` tekrarlanabilir; tek istemci için `/32` kullanılabilir.
Firewalld'nin zaten etkin olması gerekir. Kaynak tabanlı özel zone/policy düzeni varsa kurumun ağ politikasını
ayrıca kontrol edin; otomatik araç arayüzün zone'unu doğrular.

Kurucu:

- Yalnız RHEL 9.4+ x86_64/root üzerinde uygular; IP'nin atanmış olduğunu ve Skynet'in gerçekten yalnız
  `127.0.0.1:8787` dinlediğini kontrol eder. Gerekli komutlar `ip`, `ss`, `curl`, `firewall-cmd`, systemd ve Python'dur.
- RHEL paketlerinden `nginx` ve `policycoreutils` kurar; mevcut ana Nginx yapılandırmasını değiştirmez.
- `/etc/nginx/conf.d/skynet.conf` oluşturur. Aynı aracın eski dosyasını değiştirecekse önce
  `/etc/skynet/nginx-backups/` altında 0600 yedek alır; yönetilmeyen dosyayı ezmez.
- `nginx -t` başarısız olursa önceki vhost dosyasını geri getirir ve reload yapmaz. Aynı IP için çakışan vhost
  varsa reddeder. Paket/SELinux değişikliklerinin tamamını otomatik geri alma iddiası yoktur.
- Nginx'i enable/start veya reload eder. Uygulama servisine restart komutu vermez.
- Yalnız seçilen kaynak CIDR + hedef sunucu IP'si + 80 (TLS varsa 443 de) için runtime/permanent rich rule
  ekler. Tüm firewall'u reload etmez, `8787` açmaz. Mevcut başka firewall kurallarını silmez.
- SELinux'ı kapatmadan RHEL'in reverse proxy için belgelediği `httpd_can_network_connect` boolean'ını açar.
  Bu boolean sistemde `httpd_t` alanının outbound ağ bağlantılarına izin verir; özel dar kurum politikası
  kullanılıyorsa bu kısmı kurum yöneticisiyle uyarlayın.

HTTP, giriş/oturum trafiğini şifrelemez; bu seçenek kurum içi test içindir. Kalıcı kullanımda aşağıdaki HTTPS
kurulumunu kullanın.

## IP ile HTTPS

Kurum CA'sından sunucunun gerçek IPv4 adresini **subjectAltName IP** olarak içeren sertifika alın.
İstemciler bu CA'ya güvenmelidir. Kurucu kendiliğinden self-signed sertifika üretmez veya yeni uygulama
şifreleme anahtarı oluşturmaz. Nginx TLS anahtarı, Skynet'in Vault anahtarından ayrıdır.

Sertifika zincirini ve root-owned 0600 özel anahtarı sunucuya yerleştirin. Skynet servis ortamında
`SKYNET_COOKIE_SECURE=1` kullanın. Bu ortam değişikliği için uygulamayı güvenli bakım zamanında güncelleyin;
Nginx kurucusu uygulamayı yeniden başlatmaz.

```sh
sudo /opt/skynet/.venv/bin/python /opt/skynet/scripts/install_nginx_rhel.py \
  --ip 10.90.10.10 --allow-cidr 10.90.10.0/24 --zone internal \
  --tls-cert /etc/pki/tls/certs/skynet.crt \
  --tls-key /etc/pki/tls/private/skynet.key --apply
```

80, yapılandırılmış IP'deki HTTPS'e 308 yönlendirir; gelen Host başlığı yönlendirme hedefini değiştiremez.
443 aynı kaynak allowlist'ini uygular. Uygulamanın HttpOnly/SameSite oturumu korunur; TLS modunda Secure olur.
Zamanı geçmiş veya IP SAN'ı uyuşmayan sertifika ön kontrolde, cert/key uyumsuzluğu `nginx -t` aşamasında reddedilir.

## Doğrulama ve geri dönüş

İzinli başka bir makineden `http://GERCEK_IP/login` veya `https://GERCEK_IP/login` açın; giriş yapın,
hedef/tarama geçmişini ve Audit'teki istemci IP'sini kontrol edin. Nginx için:

```sh
sudo nginx -t
sudo systemctl status nginx
sudo ss -ltnp
sudo journalctl -u nginx -n 50 --no-pager
```

Nginx LAN IP'de 80/443; Skynet yalnız `127.0.0.1:8787` dinlemelidir. Yönlendirilen istemci IP başlığı Nginx'te
üzerine yazılır; uygulama forwarded header'ları yalnız doğrudan peer `127.0.0.1` ise kabul eder. Proxy cache ve
response buffering kapalıdır; mutasyonlar otomatik yeniden denenmez. Mevcut GUI polling ve ajan motoru değişmez.
Access log yalnız IP/zaman/metot/durum/boyut/süre içerir; URL sorgusu, gövde ve oturum başlığı kaydedilmez.
Nginx error log standart tanılama davranışını korur; URL'lere sır koymayın.

Önceki vhost'a dönmek için ilgili yedeği `skynet.conf` konumuna geri koyup `restorecon`, `nginx -t` ve yalnız
Nginx reload uygulayın. Eklenen rich rule'lar gerekiyorsa aynı `--zone`, kaynak/hedef/port ile hem runtime hem
`--permanent --remove-rich-rule` kullanılarak kaldırılır. Diğer sitelerin firewall kurallarını topluca temizlemeyin.
IP/CIDR değiştirilerek tekrar kurulum eski rich rule'ları otomatik silmez; eski izinleri ayrıca inceleyin.

## Kanıt ve kalan sunucu kabulü

[QA kaydı](qa/2026-11-16-nginx/README.md): UBI 9 x86_64 içinde gerçek Nginx 1.20.1 ile HTTP/HTTPS;
giriş/oturum, CSRF, kaynak allowlist, statik dosyalar, istemci IP'si, spoofed header reddi, kapalı backend portu,
erişim logunda query olmaması, IP SAN/CA doğrulaması ve HTTPS yönlendirmesi geçti. 191 unit test geçti.

Bu hazırlık sırasında gerçek RHEL test sunucusu/IP/SSH erişimi verilmedi. Host'a Nginx kurulduğu veya dış ağdan
erişim sağlandığı iddia edilmez. Gerçek sunucuda systemd, SELinux enforcing, firewalld, routing ve istemci
tarayıcısı kabulü ortam verildiğinde tamamlanacak; UBI testi bunların yerine geçmez.

Teknik dayanaklar: [Red Hat RHEL 9 Nginx rehberi](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/deploying_web_servers_and_reverse_proxies/index#configuring-nginx-as-a-reverse-proxy-for-the-http-traffic_setting-up-and-configuring-nginx),
[Nginx proxy modülü](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).
