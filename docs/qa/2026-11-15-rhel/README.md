# RHEL hazırlığı ve QA — 15 Kasım 2026

Kullanıcının hedefi **RHEL 9.4+ x86_64**. Kurulum adımları: [RHEL.md](../../RHEL.md).
Bu çalışma asıl kurulumun verisini veya anahtarını değiştirmedi; migration/deploy/commit yapmadı.

## Ortam ve sonuç

| Kontrol | Sonuç / kanıt |
| --- | --- |
| Linux kullanıcı alanı | Resmi Red Hat UBI 9 / Python 3.12, linux/amd64; Apple silicon Docker host üzerinde emülasyon |
| Python / ABI | 3.12.15 / glibc 2.34; uygulama UID 1001 |
| Linux testleri | **148/148 OK** · [linux-tests.txt](linux-tests.txt) |
| macOS regresyon | **148/148 OK** · [macos-tests.txt](macos-tests.txt) |
| Resmi Linux Strix | 1.7.0 binary çalıştı; wheel SHA-256 doğrulandı · [linux-artifact.txt](linux-artifact.txt) |
| Native CLI seçenekleri | `--target`, `--instruction-file`, `--workspace-file`, `--non-interactive` yardım çıktısında doğrulandı · [strix-linux-help.txt](strix-linux-help.txt) |
| Servis birimi | Linux `systemd-analyze verify` exit 0 · [systemd-verify.txt](systemd-verify.txt) (hatasız komut boş çıktı verir) |
| Gerçek HTTP | Login, 401, CSRF 403, CSP/nosniff, hedef, Vault, kampanya ve devre dışı zamanlama · [önce](http-before-restart.json), [restart sonrası](http-after-restart.json) |
| Anahtar kalıcılığı | Restart aynı anahtar baytlarını ve 0600 izinlerini korudu · [key-persistence.json](key-persistence.json) |
| Doctor | Mevcut şifreli Vault kaydı aynı anahtarla çözüldü; hiçbir sır yazdırılmadı · [doctor-after-restart.json](doctor-after-restart.json) |
| Tarayıcı QA | 12 görünüm × 1366×768 ve 1920×1080; sayfa genelinde yatay taşma ve JS konsol hatası yok · [browser-checks.json](browser-checks.json) |

İmaj [Containerfile.qa](../../../deploy/rhel/Containerfile.qa) ile oluşturuldu. Son testler, bu imajın
kurulu bağımlılıkları üzerinde güncel `skynet`, `tests` ve `scripts` dizinleri salt okunur mount edilerek
çalıştırıldı. İki venv'in `pip check` kontrolleri geçti. Shell/Python/JavaScript sözdizimi ve diff kontrolü geçti.
İmaj hash'i Containerfile'da sabit; bağımlılıklar iki lock dosyasında sabit.

## HTTP ve görsel QA'nın kapsamı

1. Boş, geçici Linux verisiyle gerçek `python -m skynet` başlatıldı. Hedef ve sağlayıcı kayıtları açıkça QA
   olarak adlandırıldı. LiteLLM test adresine bağlantı yapılmadı; zamanlama devre dışı bırakıldı. Hiç tarama yok.
2. Docker restart sonrasında aynı kayıt kimlikleri ve Vault okunabilirliği doğrulandı. Anahtar özeti yalnız
   konteyner içinde karşılaştırıldı; anahtar veya özeti rapora alınmadı.
3. Ayrı Linux HTTP sunucusunda daha önce izinli yerel hedefte elde edilen 17/18/19 numaralı çalışmaların
   kopyaları açıldı. Bu sunucuda lifespan yalnız DB/auth başlatır; worker, scheduler, import, backfill ve recovery
   çalıştırılmaz. Eski bir kaydı görüntülemek hiçbir hedefi yeniden taramaz.
4. Targets, Campaigns, Schedules, Auth profiles, Settings, Coverage, Session health, Timeline, Instructions,
   Browser, Evidence workspace ve Compare görüntülendi. Kapsam endpoint/rol filtresi ve hücre ayrıntısı;
   803/804 numaralı maskeli kanıtların response farkı; 561 olayın replay yüklemesi, Home → Play ilerlemesi;
   İngilizce Download menüsü kontrol edildi. Remediation Open kaldı.
5. Ekran görüntüleri `*-1366.jpg` / `*-1920.jpg` dosyalarıdır. Tam sayfa görüntüleri daha uzundur;
   viewport boyutları DOM ölçümlerinde kayıtlıdır. Timeline son ekranı Scan filtresindedir (3 kayıt);
   filtresiz oynatmada 561 kayıt yüklendi.

QA konteynerleri host Docker soketine erişmez. Bu yüzden UI'daki **Docker is down** beklenen gerçek durumdur;
doctor `--skip-docker` ile çalıştı ve `docker_checked: false` yazdı. Bu sonuç tam tarama hazırlığı iddiası değildir.
Bu çalışmada yeni Strix/LLM pentesti başlatılmadı; Linux üzerinde gerçek ajan talimatı teslimi testi yapılmadı.
Önceki macOS mesajlaşma çalışmasının kanıtı PROGRESS.md'de ayrı kayıtlıdır.

## Düzeltilenler

- Önceki yalnız macOS artifact seçimi: resmi Linux x86_64 wheel ve platform seçimi.
- RHEL'in varsayılan Python 3.9'una düşme: Python 3.12 seçimi ve anlaşılır erken hata.
- Doctor venv `bin/python` symlink'ini çözerek sistem Python'unu seçiyordu: venv yolu korunuyor.
- `verify._http` Caido'nun açıkça tam olarak işaretlediği gövdesiz GET görünümünü reddediyordu:
  yalnız geçerli ve kesin olarak gövdesiz istek için istisna. Eksik gövde, kısmi yanıt ve belirsiz başlıklar reddedilir.
  Evidence aynı parser'ı kullanır. Verify sonuç kuralları ve version=2 değişmedi; eski sonuçlar korunur.
- İndirme menüsündeki kalan Türkçe uygulama etiketleri İngilizceye çevrildi. Kullanıcı verisi yeniden yazılmadı.

## Gerçek RHEL sunucusunda kalan kabul

- [ ] Python 3.12 ve Docker Engine kurulumu; servis hesabıyla **Docker kontrolünü atlamadan** doctor.
- [ ] Taşınıyorsa tutarlı DB/run yedeği, mevcut anahtar, relocate dry-run ve gerekiyorsa apply.
- [ ] systemd üzerinden başlatma/restart/boot; SELinux enforcing ve dosya izinleri.
- [ ] Sandbox ağ erişimi; kurum içi LiteLLM/CA, izinli yerel hedefte tarama, iptal ve ajan mesajı.
- [ ] FIPS etkinse kurumun kripto politikasında ayrıca doğrulama.

UBI 9 testi RHEL kullanıcı alanı ve x86_64 native binary uyumuna kanıttır; gerçek RHEL kernel/SELinux/systemd
boot veya Docker sandbox kabulünün yerini tutmaz. Browser hâlâ metadata sunar; canlı görüntü akışı yoktur.
