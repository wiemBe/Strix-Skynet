# RHEL 9.4+ x86_64 kurulumu

Hedef: RHEL 9.x (9.4 veya üstü), x86_64, Python 3.12 ve çalışan Docker Engine.
Strix motoru/orkestrasyonu değişmez; resmi Strix 1.7.0 Linux wheel'i ve kilitli bağımlılıklar kurulur.

RHEL 9'un varsayılan Python'u 3.9'dur; 3.12 paketleri 9.4 ile gelir. Sistem Python'unu değiştirmeyin.
[Red Hat Python kurulum rehberi](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/epub/installing_and_using_dynamic_programming_languages/assembly_introduction-to-python_installing-and-using-dynamic-programming-languages).

## 1. Sistem bağımlılıkları

Bu değişiklikleri içeren checkout'u hedef sunucuya aktarın. macOS `.venv` / `.strix-runtime` klasörlerini taşımayın.

```sh
sudo dnf install python3.12 python3.12-pip git tar
python3.12 --version
```

Docker yoksa kurumun onaylı Docker kurulumunu kullanın. Resmi RHEL repository yöntemi:

```sh
sudo dnf install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker info
```

[Docker'ın RHEL rehberi](https://docs.docker.com/engine/install/rhel/).
Kurucu mevcut Podman/runc paketlerini kaldırmaz; paket çakışması varsa kurum yöneticisi çözmelidir.
Bu kurulum Docker Engine içindir; Podman API uyumluluğu doğrulanmış sayılmaz.

## 2. Servis kurulumu

```sh
cd /path/to/Strix
sudo bash scripts/install_rhel.sh
```

Kurucu `/opt/skynet` kodunu ve iki ayrı venv'i hazırlar; `skynet` servis hesabını ve systemd birimini oluşturur.
Servisi **başlatmaz**. Çalışan bir Skynet varsa güncellemeyi reddeder: önce taramaları sonlandırıp servisi durdurun.
Mevcut `/etc/skynet/skynet.env`, veri ve şifreleme anahtarı korunur; kod aktarımı `.env`, data, anahtar ve QA kayıtlarını kapsamaz.

| Yol | İçerik |
| --- | --- |
| `/opt/skynet` | Kod, `.venv`, `.strix-runtime`; servis tarafından salt okunur |
| `/etc/skynet/skynet.env` | root:root, 0600 servis yapılandırması |
| `/var/lib/skynet` | Veritabanı, loglar, runtime dosyaları ve çalışma dizini; 0700 |
| `/var/lib/skynet-keys/secret.key` | Mevcut anahtar veya yalnız yeni kurulumda oluşturulan anahtar; 0600 |
| `/var/lib/skynet/work/strix_runs` | Strix çalışma çıktıları |

Servisin Docker soketine `SupplementaryGroups=docker` ile erişimi vardır. Bu erişim host üzerinde güçlü yetki verir;
yalnız güvenilen Skynet yöneticilerine erişim açın. [Docker grup yetkileri](https://docs.docker.com/engine/install/linux-postinstall/).
`PrivateTmp` kullanılmaz: Strix'in Docker daemon'una verdiği geçici host yolları görünür kalmalıdır.

## 3. Yeni kurulum veya mevcut verinin taşınması

**Yeni kurulum:** boş veri dizininde ilk açılış anahtarı oluşturabilir. `SKYNET_PASSWORD` boşsa rastgele giriş
şifresi `/var/lib/skynet/admin_password.txt` dosyasına yazılır. Kullanıcı `admin`.

**Mevcut kurulum:** uygulamayı açmadan önce aynı anahtarı ve tutarlı DB yedeğini taşıyın. Yeni anahtar üretmeyin.
Eski sistemde zamanlamaları duraklatın, kuyruğu boşaltın ve çalışan taramaları sonlandırın.
Eski DB'nin kopyasını alırken yalnız `cp skynet.db` kullanmayın; WAL dahil backup API kullanın:

```sh
python3 - /old/data/skynet.db /safe/export/skynet.db <<'PY'
import sqlite3, sys
from contextlib import closing
from pathlib import Path
with closing(sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + '?mode=ro', uri=True)) as src:
    with closing(sqlite3.connect(sys.argv[2])) as dst:
        src.backup(dst)
PY
```

Mevcut anahtarı ayrı ve güvenli bir kanaldan taşıyın. Sunucuda örnek yerleştirme (kaynaklar sizin aktardığınız dosyalardır):

```sh
sudo install -o skynet -g skynet -m 0600 /safe/import/skynet.db /var/lib/skynet/skynet.db
sudo install -o skynet -g skynet -m 0600 /safe/import/existing-secret.key /var/lib/skynet-keys/secret.key
```

Geçmiş çalışma klasörlerini `/var/lib/skynet/work/strix_runs/<aynı-run-name>` olarak kopyalayın; servis hesabına
okuma/yazma izni verin. DB'de eski macOS yolları kalabileceği için önce aşağıdaki **değişiklik yapmayan** planı inceleyin:

```sh
sudo -u skynet /opt/skynet/.venv/bin/python /opt/skynet/scripts/relocate_runs.py \
  --data /var/lib/skynet --workdir /var/lib/skynet/work --strix /opt/skynet/.strix-runtime/bin/strix
```

Plan doğruysa aynı komuta `--apply` ekleyin. Araç önce tutarlı, 0600 bir DB yedeği alır; yalnız run yolları ve
`strix_bin` / `strix_workdir` ayarlarını günceller. Anahtara, şifreli değerlere, orijinal kanıtlara ve sonuçlara dokunmaz.
Aktif/kuyrukta tarama veya etkin zamanlama varsa reddeder. Eksik klasörleri listeler; bunları geri yükleyin veya
`--allow-missing` seçeneğini inceleyin (eksik geçmiş kayıtları silmez, eski yollarını korur).

## 4. Doctor ve başlangıç

Servis hesabı ve aynı Docker grubuyla kontrol edin:

```sh
sudo -u skynet -g docker /opt/skynet/.venv/bin/python /opt/skynet/scripts/doctor.py \
  --data /var/lib/skynet --key-file /var/lib/skynet-keys/secret.key \
  --workdir /var/lib/skynet/work --runtime /opt/skynet/.strix-runtime/bin/python
```

Doctor DB'yi salt okunur açar; migration yapmaz, anahtar oluşturmaz ve pentest başlatmaz.
Mevcut DB ayarları ortam varsayılanlarına göre önceliklidir: eski `strix_bin` yolu varsa bunu gizlemez.
Yukarıdaki relocate aracıyla düzeltin. Özel Docker endpoint/CA yapılandırması kullanıyorsanız aynı değişkenleri
doctor sürecine de güvenli biçimde aktarın; anahtar/parolaları komut satırına yazmayın.

```sh
sudo systemctl enable --now skynet
sudo systemctl status skynet
sudo journalctl -u skynet -n 100 --no-pager
```

Varsayılan yalnız `127.0.0.1:8787`'dir. Yerel erişim için SSH tüneli:

```sh
ssh -L 8787:127.0.0.1:8787 your-user@rhel-host
```

Tarayıcıda `http://127.0.0.1:8787`. Kurumsal HTTPS proxy kullanırken `SKYNET_COOKIE_SECURE=1` ayarlayın.
IP yazarak doğrudan ağdan erişim için **aynı sunucuya Nginx** kurulumu ve kurulum komutu:
[NGINX.md](NGINX.md). Bu kurulum backend'i loopback'te tutar, gerçek IP ve istemci CIDR allowlist'iyle
80/443 üzerinden proxy sağlar; `8787` firewall'a açılmaz. IP atanması veya gerçek RHEL erişimi bu repoda yapılmış sayılmaz.
SELinux/firewalld kapatılmaz; proxy veya özel yol için AVC reddi varsa kurum politikasıyla çözün.
Sistem genelinde TLS doğrulamasını veya kripto politikasını düşürmeyin. FIPS etkin kurulumda ayrıca kabul testi gerekir.

Linux'te `host.docker.internal` Docker host-gateway'dir; host'un 127.0.0.1 loopback arayüzü değildir.
Yalnız loopback'e bind edilmiş test uygulamasına sandbox erişemeyebilir. İzinli özel bridge adresini veya
kurumun onayladığı hedef ağını kullanın; test hedefini bunu çözmek için kendiliğinden public arayüze açmayın.

## 5. Çalıştırma / güncelleme sınırları

- Tek uygulama süreci kullanılır (`python -m skynet`). Çoklu Uvicorn worker scheduler/kuyruğu çoğaltır.
- OpenRouter ve LiteLLM, GUI'deki kalıcı profillerle seçilir; sağlayıcılar arasında otomatik fallback yoktur.
- Messaging Settings'ten açılır; Linux binary ve `.strix-runtime` sürümleri aynı olmalıdır.
- Strix wheel'i `SHA256SUMS` ile doğrulanır. `requirements-app.lock` ve `vendor/strix/requirements.lock` ayrı ortamlardır.
- `scripts/setup_strix.sh --force` yalnız servis/taramalar durduktan sonra kullanılmalı; eski runtime yedeklenir,
  kurulum başarısız olursa geri konur. Veri ve anahtar bu işlemde değiştirilmez.
- Şifreli veri olup anahtar yoksa uygulama yeni anahtar üretmeyi reddeder; mevcut anahtarı geri yükleyin.

## 6. Tekrarlanabilir Linux QA

```sh
docker build --platform linux/amd64 -f deploy/rhel/Containerfile.qa -t skynet-rhel9-qa:local .
docker run --rm --platform linux/amd64 skynet-rhel9-qa:local
```

QA imajı Docker yerine rootless Podman ile de çalıştırılabilir:

```sh
podman build --platform linux/amd64 -f deploy/rhel/Containerfile.qa -t localhost/skynet-rhel9-qa:local .
podman run --rm --platform linux/amd64 localhost/skynet-rhel9-qa:local
podman build --platform linux/amd64 -f deploy/rhel/Containerfile.nginx-qa -t localhost/skynet-nginx-qa:local .
podman run --rm --workdir /opt/skynet localhost/skynet-nginx-qa:local \
  .venv/bin/python scripts/qa_nginx.py --disposable-qa
```

Bu Podman desteği yalnız QA içindir; üretim Strix sandbox'ının Podman API ile uyumlu olduğu anlamına gelmez.
[16 Kasım yeniden test ve düzeltme kaydı](qa/2026-11-16-rhel-codex/README.md): 193 test,
gerçek HTTP/HTTPS proxy ve uygulama yeniden başlatma/şifreli veri kalıcılığı kontrolleri geçti.

Bu imaj resmi Red Hat UBI 9 / Python 3.12 tabanıdır; host veri/anahtarları ve Docker soketi paylaşılmaz.
Unit/API/native SDK testleri gerçek LLM/Docker sandbox pentesti başlatmaz.
`scripts/qa_http.py` yalnız **ayrı, boş bir QA servisine** `--disposable-qa` ile kullanılmalıdır;
üretim örneğinde çalıştırmayın. Kalıcı QA kaydı ve gerçek makine üzerinde kalan kabul maddeleri PROGRESS.md'dedir.

UBI konteyner testi RHEL kullanıcı alanı/ABI'sini doğrular; gerçek sunucuda systemd boot, SELinux ve
Docker sandbox erişimi için son kabul kontrolünün yerini tutmaz.
