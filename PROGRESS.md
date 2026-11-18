# Skynet — çalışma takibi

Güncelleme: 17 Kasım 2026 · Europe/Istanbul (son çalışma: farklı model ve LiteLLM ile uçtan uca tarama testi)

## Farklı model / LiteLLM testi ve menü düzeltmesi — Claude, 17 Kasım 2026

- [x] “⋯” işlem menüleri `.table-card { overflow: hidden }` içinde kırpılıyordu (ör. LLM bağlantı satırı).
  Menü açılınca pencereye göre konumlanıyor (CSSOM, CSP uyumlu); altta yer yoksa yukarı açılıyor; Esc, kaydırma
  ve pencere boyutu değişince kapanıyor. Gerçek uygulamada doğrulandı (`0377157`).
- [x] Model devralma: Skynet profili `STRIX_LLM`/`LLM_API_KEY`/`LLM_API_BASE` hem ortam değişkeni hem `--config`
  dosyası olarak veriyor; Strix 1.7 yükleyicisinde ortam değişkeni önce gelir. `~/.strix/cli-config.json` başka
  model gösterirken Strix'in profil modelini çözdüğü çevrimdışı doğrulandı.
- [x] OpenRouter · `anthropic/claude-haiku-5.5` (Lokal test hedefi, quick): #19 `MaxTurnsExceeded (3)` ile
  durdu — kök ajan 3. turda `finish_scan` çağırdığı hâlde sınır aşıldı sayıldı; model hatası değil. #20 (10 tur)
  **tamamlandı**: 18 istek, hepsi Haiku, hepsi 200; rapor üretildi; Strix maliyeti $0.024.
- [x] LiteLLM: yerel proxy (1.109.1, `127.0.0.1:4000`, takma ad `haiku-gw` → OpenRouter Haiku, master key).
  Bağlantı testi: yanlış anahtar → hata, yanlış model → “bulunamadı”, doğru ayar → “available”.
  #21 **tamamlandı**: Strix `openai/haiku-gw` çözdü; 37 isteğin tamamı `host=127.0.0.1`, 200; proxy günlüğü eşleşiyor.
- [x] Üç test taraması OpenRouter'da toplam ~$0.27 harcadı. Test bağlantıları ve proxy sonra kaldırıldı;
  #19–#21 geçmişte duruyor. Varsayılan bağlantı (DeepSeek) değişmedi.
- [x] Birleşmiş 17 dal (yerel 8, GitHub 9) silindi; yalnız `main` kaldı.
- LiteLLM takma adlarında (ör. `haiku-gw`) Strix maliyet hesaplayamıyor (“Strix couldn't calculate”); kurum
  gateway'inde maliyet gateway panelinden izlenmeli. Token sayısı görünüyor.
- Boş veri klasörüyle ilk açılışta uygulama `~/.strix/cli-config.json` içindeki gerçek LLM anahtarını otomatik
  profile alıyor (`llm.migrate_from_strix_cli_config`). Demo/QA örneklerinde önce sahte profil oluşturulmalı.
- Gerçek RHEL/kurum LiteLLM gateway'i (virtual key, DB'li 401 yanıtı, özel CA) ile test yapılmadı.

## Bulgu kartı ve SIEM/Syslog entegrasyonu — Claude, 17 Kasım 2026

- [x] `origin/main` çekildi (PR #8 RHEL düzeltmeleri, PR #9 README görüntüleri); yereldeki SIEM/Syslog çalışması
  korunarak üstüne alındı. PROGRESS çakışması iki tarafın bölümleri tutularak çözüldü.
- [x] SIEM/Syslog çalışması (aşağıdaki iki Codex bölümü) ayrı commit olarak main'e alındı.
- [x] Hedef/kampanya “Finding groups” kartı yeniden tasarlandı: açık sayı başlığı, durum etiketleri, önem başına
  dağılım çubuğu (parlak = açık, soluk = çözülmüş), hizalı sütunlar, açığı olmayan satırda “Resolved”.
  “1 groups / 1 scans” tekil-çoğul hataları düzeltildi.
- [x] “Open critical / high” istatistik kutusu, `alert` bileşen sınıfıyla çakıştığı için yatay diziliyordu;
  sınıf `is-alert` olarak ayrıldı (genel bakış ve kampanya).
- [x] Ayrı veri klasörü/anahtar/portta (8790) sentetik demo ile karışık, false positive ve tamamı çözülmüş
  durumlar; 1600 × 1050 ve 768 genişlikte taşma/konsol hatası yok. Asıl veritabanı değiştirilmedi.
- [x] `target-details.jpg` ve `campaign.jpg` yeniden alındı ([notlar](docs/screenshots/README.md)).
- [x] macOS'ta **214/214 test OK**.
- Telefon genişliğinde (375 px) tüm uygulama sabit kenar çubuğu nedeniyle sıkışıyor; bu karttan bağımsız, ayrı iş.

## README ekran görüntüleri — Codex, 17 Kasım 2026

- [x] Güncel uygulamadan altı yeni görüntü: hedef detayları, kampanya, envanter, kimlik profilleri,
  yönetim raporu ve audit log. README'ye açıklamalı galeri ve ilk kullanım adımları eklendi.
- [x] Ayrı UBI 9 demo veritabanı kullanıldı; örnek veriler açıkça etiketlendi. Canlı tarama/sağlayıcı isteği yok.
- [x] 1600 × 1050 ve 1366 × 768 görünüm kontrolünde yatay taşma veya JavaScript hatası görülmedi;
  tüm görseller incelendi. Uygulama kodu değişmedi; mevcut 193 testlik backend kaydına bağlantı eklendi.
- Görseller ve kaynak/kontrol bilgileri: [docs/screenshots](docs/screenshots/README.md).

## RHEL UBI 9 yeniden testi ve düzeltmeler — Codex, 16 Kasım 2026

- [x] `wiemBe/Strix-Skynet` reposu `09ad607` commit'inden klonlandı; çalışma branch'i `fix/rhel-qa`.
- [x] Resmi, digest ile sabitlenmiş UBI 9 x86_64 imajı oluşturuldu. Python 3.12.15 / glibc 2.34;
  başlangıçta **191 test**, düzeltme ve ek regresyonlarla **193 test** geçti. Native Strix testleri atlanmadı.
- [x] Doctor'ın `False` dönen yetenek kontrolünü başarılı sayması düzeltildi.
- [x] Eksik anahtar koruması şifreli ajan mesajlarını ve analist not revizyonlarını da kapsıyor;
  yalnız bu kayıtlar kalsa bile yeni anahtar oluşturulmuyor. SQLite URI özel karakterleri olan veri yolları düzeltildi.
- [x] Nginx QA, Podman'ın `/run/.containerenv` işaretini tanıyor. Gerçek Nginx 1.20.1 üzerinde HTTP/HTTPS,
  giriş/oturum, CSRF, CIDR, Secure cookie, forwarded header, TLS SAN/CA ve kapalı backend kontrolleri geçti.
- [x] Tam uygulama başlangıcı → fixture kayıtları → kapat/aç → kayıtları doğrula; anahtar ve şifreli değerler
  değişmedi. SQLite integrity ve Docker hariç tüm doctor kontrolleri geçti.
- [x] RHEL systemd 252 ile unit doğrulaması, iki ortamda pip check, Python/JS/shell sözdizimi geçti.
- [x] Önce/sonra kanıtları ve tekrar komutları: [QA raporu](docs/qa/2026-11-16-rhel-codex/README.md).
- Gerçek RHEL host boot/systemd, SELinux enforcing, firewalld ve Docker sandbox pentesti yapılmadı.
  Host verileri/anahtarları paylaşılmadı; LLM veya dış hedef taraması başlatılmadı.

## Syslog tekrar QA — Codex, 16 Kasım 2026

[Tekrar üretimler, testler ve ekranlar](docs/qa/2026-11-16-syslog-repeat/README.md).

- [x] Dört kusur kapatıldı: yeni başarılı olayın gizlediği pending hata, JSON'a benzeyen audit özetinin
  türünün değişmesi/audit API sorunu, yavaş gönderimin retry aralığını tüketmesi ve form hatasında takılı kalan test durumu.
- [x] Probe sonucu test edilen endpoint'i gösteriyor; form değişince eski sonuç temizleniyor.
- [x] Altı yeni regresyonla **212/212 test OK**; UBI 9 x86_64'te **21/21 syslog testi OK**.
  Tam test çıktısındaki SQLite ResourceWarning'ler raporda ayrıca kayıtlı.
- [x] Ayrı süreç kapanıp açıldıktan sonra pending olay gerçek localhost TCP alıcısına aynı event_id ile ulaştı.
- [x] 1366×768 / 1920×1080: validation/probe/TLS hata/Viewer ekranları incelendi; yatay taşma ve konsol hatası yok.
- [x] Gerçek yerel servis, aktif tarama ve etkin zamanlama olmadığı doğrulanarak güncel kodla yeniden açıldı.
  Schema 8, mevcut anahtar/oturum korundu; syslog kapalı/collector boş. Yeni pentest veya migration yok.
- [ ] Kurum SIEM'i ingestion ve gerçek RHEL host kabulü hâlâ ayrı; collector/host bilgisi verilmedi.

Geçici QA sunucusu/verileri temizlendi; gerçek uygulama sağdaki tarayıcıda açık. Bu değişiklikler commit/push edilmedi.

## SIEM / Syslog — Codex, 16 Kasım 2026

[Kurulum ve teslim anlamı](docs/SYSLOG.md), [test/görsel QA kanıtları](docs/qa/2026-11-16-syslog/README.md).

- [x] Admin Settings → SIEM / Syslog: RFC 5424 + JSON, UDP/TCP/TLS, optional mTLS, facility/source/CA/hostname alanları.
- [x] Merkezi audit kaynağı; aynı SQLite transaction'ında outbox. Request handler network gönderimi yapmıyor.
- [x] Kalıcı retry, sabit event_id, 10.000 pending sınırı/overflow görünürlüğü; yeni hedefe eski kuyruk taşınmıyor.
- [x] Göndermeden önce güncel/tarihsel maskeleme; okunamayan bağlamda gönderim yok. TLS doğrulaması zorunlu.
- [x] Test probe, pending/handoff/hata sayaçları; handoff SIEM ingestion onayı olarak sunulmuyor.
- [x] İlk uygulama aşamasında 15 yeni testle macOS'ta **206/206 OK**; UBI 9 x86_64'te syslog **15/15 OK**.
- [x] 1366×768 / 1920×1080 form, TLS, UDP probe/handoff, TCP retry ve Viewer görsel QA. Taşma/konsol hatası yok.
- [x] Çalışan yerel uygulama, boş kuyruk/zamanlama kontrolünden sonra migration 8 ile güncellendi; önce tutarlı
  yedek alındığı doğrulandı. Mevcut anahtar ve kullanıcı oturumu korundu; yeni pentest başlatılmadı.
- [ ] Gerçek kurum SIEM'i parser/indexer alımı ve RHEL host egress/SELinux kabulü; collector bilgisi verilmedi.

Yerel gerçek uygulamada forwarding **kapalı**, collector boş. QA yalnız kendi sentetik verisi ve localhost
UDP/TCP/TLS alıcılarını kullandı. Yeni kod bu turda commit/push edilmedi; önceki main entegrasyonu aşağıda kayıtlı.

## Main entegrasyonu — Codex, 16 Kasım 2026

- [x] Origin yenilendi; yeni uzak değişiklik yoktu. Claude'un `4f04aa2` kullanıcı/rol/audit/rapor commit'i korundu.
- [x] `00275fc` commit'i: R1–R5 düzeltmeleri, görsel QA, migration 7 ve aynı sunucu Nginx kurulum/QA dosyaları.
- [x] `users-roles-audit-report` branch'i main'e çakışmasız fast-forward alındı; geçmiş yeniden yazılmadı.
- [x] Main'e alınan aynı uygulama koduyla **191/191 test OK**; JS, shell ve staged diff kontrolü geçti.
- [x] Mevcut yerel/origin branch uçlarının main geçmişinde bulunduğu doğrulandı. Branch'ler silinmedi.
- Gerçek RHEL sunucusu hâlâ verilmedi; Nginx host kurulumu/deployment yapılmadı. Asıl DB/anahtar ve taramalar
  değiştirilmedi. Aşağıdaki “commit/push yapılmadı” ifadeleri ilgili QA adımlarının tarihsel durumudur.

## Aynı sunucuda Nginx / IP ile erişim — 16 Kasım 2026

Kullanıcı Nginx'in uygulamayla aynı sunucuya kurulmasını istedi; `10.90.10.10` örnek adres, gerçek test ortamı
henüz verilmedi. [Kurulum](docs/NGINX.md), [QA](docs/qa/2026-11-16-nginx/README.md).

- [x] RHEL 9.4+ x86_64 için dry-run/--apply kurucu: gerçek atanmış IP, istemci CIDR allowlist'i ve firewall zone'u.
- [x] Nginx IP'de 80/443; backend yalnız 127.0.0.1:8787. Aynı IP'deki varsayılan vhost, tüm GUI/API proxy'si.
- [x] HTTP ve sağlanan IP SAN'lı sertifikayla HTTPS; sabit IP'ye redirect, Secure cookie uyumu.
- [x] Scoped firewalld rich rule'ları, RHEL reverse proxy SELinux boolean'ı; mevcut nginx.conf korunuyor.
  Managed vhost yedeği ve başarısız nginx -t halinde dosya geri yükleme. Skynet restart edilmiyor.
- [x] Proxy cache/buffering/retry kapalı; istemci IP başlıkları üzerine yazılıyor. Uvicorn yalnız loopback peer'e güveniyor.
- [x] Gerçek UBI 9 x86_64 / Nginx 1.20.1 ile HTTP+HTTPS login/session/CSRF/ACL/static/IP-spoof/log/redirect testleri geçti.
- [x] 8 yeni deployment testiyle **191/191 test OK**; shell/diff kontrolü geçti.
- [ ] Gerçek RHEL host IP/SSH bilgisi verilince paket/servis/firewall/SELinux uygulaması ve uzak tarayıcı kabulü.

Bu turda gerçek host'a Nginx kurulmadı, IP atanmadı; Mac ağı değiştirilmedi. Asıl DB/anahtar/taramalar korunuyor.
Yerel QA konteyneri host portu yayınlamadı; yalnız geçici kayıtlarla çalıştı. Commit/merge/push yapılmadı.

## Kullanıcı/audit/rapor düzeltmeleri ve görsel QA — Codex, 16 Kasım 2026

[Düzeltme raporu](docs/reviews/2026-11-16-users-audit-report-fixes.md),
[QA ekranları ve test çıktıları](docs/qa/2026-11-16-users-fixes/README.md).

- [x] R1 — Audit metadata'sı güncel ve saklanan eski sırlarla yazmadan/kesmeden önce, ayrıca okurken maskeli.
- [x] R2 — Disable eski oturumları kalıcı iptal ediyor; re-enable eski çerezle giriş sağlamıyor.
- [x] R3 — Sabit Fixed geçiş zamanı; not düzenlemesi süreyi değiştirmiyor. Eski belirsiz zamanlar Unknown.
- [x] R4 — Raporun başlık/hedef/kampanya metadata'sı ve hazırlayan adı da maskeli.
- [x] R5 — Viewer workspace mutasyonları gizli, not editörü yok; Analyst işlevleri korunuyor.
- [x] QA'da bulunan Control-only aynı istek seçimi ve uzun rol açıklamasındaki kart hizası düzeltildi.
- [x] 9 yeni regresyonla **183/183 test OK**; JS/diff kontrolü geçti.
- [x] 1366×768 / 1920×1080, 32 görüntü; Admin/Analyst/Viewer etkileşimleri, formlar ve raporlar incelendi.
  Ölçülen sayfalarda yatay taşma ve browser warning/error yok.
- Migration 7 hazır: tutarlı yedek sonrası session_version/fixed_at ve eski audit metadata gizlilik onarımı.
  Asıl DB/anahtar değiştirilmedi; yalnız geçici fixture'lar migrate edildi. Eski yedekler yeniden yazılmaz.
  Gerçek PDF/RHEL sunucu kabulü bu turda yapılmadı. Commit/merge/push yapılmadı.

## Kullanıcı, audit ve rapor — tarihsel inceleme, 16 Kasım 2026

Aşağıdaki beş kusur yukarıdaki düzeltmelerle kapatıldı; bölüm ilk incelemenin tarihsel kaydıdır.

İncelenen yeni commit `4f04aa2`, branch `users-roles-audit-report`.
[İnceleme ve tekrar üretim adımları](docs/reviews/2026-11-16-users-audit-report-review.md),
[QA kanıtları](docs/qa/2026-11-16-users-review/README.md).

- [x] 174/174 mevcut test; JavaScript sözdizimi ve diff kontrolü geçti.
- [x] Admin ve Viewer ekranları 1366×768 / 1920×1080'de incelendi; yatay taşma/konsol hatası görülmedi.
- [ ] R1/P1 — Audit özeti bilinen Vault sırrını açık metin saklayıp döndürüyor.
- [ ] R2/P2 — Devre dışı bırakılıp açılan hesapta eski oturum çerezi yeniden geçerli oluyor.
- [ ] R3/P2 — Fixed bulgunun yalnız notunu değiştirmek rapordaki düzeltme süresini değiştiriyor.
- [ ] R4/P2 — Rapor başlığı/hedef metadata'sı bilinen sır maskelemesini atlıyor.
- [ ] R5/P3 — Viewer'a sunucunun reddettiği düzenleme düğmeleri gösteriliyor.

Uygulama kodu değiştirilmedi; merge/push yapılmadı. Yalnız izole fixture DB/anahtar kullanıldı;
Strix/LLM/dış hedef çalıştırılmadı. Yeni RHEL kabulü ve PDF üretimi yapılmadı.

## Branch'lerin main üzerinde birleştirilmesi — Codex, 16 Kasım 2026

- [x] Origin yenilendi; çalışma ağacı temizdi. Son Claude commit'i `4f1fef1`
  (`Add SKY workspace, RHEL deployment and agent tree fixes`) main'e fast-forward ile alındı.
- [x] Tüm mevcut yerel ve origin feature branch uçlarının bu commit'in geçmişinde bulunduğu doğrulandı;
  önceki bütçe/turn kararları, paketlenmiş Strix, SKY, RHEL ve görsel QA düzeltmeleri korundu.
- [x] Birleştirilen uygulama koduyla `.venv/bin/python -m unittest discover -s tests` → **151/151 OK**.
  app.js/sky.js JavaScript sözdizimi, kurulum shell sözdizimi ve diff kontrolü geçti.
- Bu işlemde yeni Strix/LLM taraması, deployment veya asıl data/anahtar değişikliği yapılmadı.
  Önceki RHEL ve özellik kabul sınırları devam ediyor. Feature branch'ler silinmedi.

## Tekrar görsel QA — Codex, 15 Kasım 2026

- [x] Taramanın 12 sekmesi, kanıt çalışma alanı, karşılaştırma ve dialog'lar 1366×768 / 1920×1080'de tekrar incelendi.
- [x] Laptopta kesilen son sekme, kısalan oturum metinleri ve sıkışık hücreler düzeltildi.
- [x] Uzun dialog gövdesi kaydırılabilir; başlık/alt eylemler viewport içinde kalıyor.
- [x] Details talimatındaki 145px yatay taşma ve kart üst hizası düzeltildi; “Mod” etiketi “Mode” oldu.
- [x] 41 ekran görüntüsü; son 38 ölçümde taşma/kesilen sekme/ekran dışı alt eylem ve JS konsol hatası yok.
  Ajan filtresi, kanıt Open/Close, maskeli fark ve form Cancel etkileşimleri doğrulandı; JS/diff kontrolü geçti.

Kanıtlar, kapsam ve sınırlar: [docs/qa/2026-11-15-visual-repeat/README.md](docs/qa/2026-11-15-visual-repeat/README.md).
Yalnız izole geçmiş kopyası; yeni pentest, ajan mesajı veya asıl veri/anahtar değişikliği yok.

## RHEL 9.4+ x86_64 ve tekrar QA — Codex, 15 Kasım 2026

Kurulum: [docs/RHEL.md](docs/RHEL.md). Kanıtlar ve kalan sunucu kabulü:
[docs/qa/2026-11-15-rhel/README.md](docs/qa/2026-11-15-rhel/README.md).

- [x] Resmi Strix 1.7.0 Linux x86_64 wheel'i, SHA-256 doğrulaması ve platform seçimi eklendi.
  macOS arm64 kurulumu korunuyor. İki ayrı bağımlılık kilidi; başarısız zorunlu runtime kurulumunda geri dönüş.
- [x] RHEL Python 3.12 kurucusu, ayrı servis hesabı, tek süreç systemd birimi ve ortam örneği.
  Kod /opt, veri /var/lib, anahtar ayrı /var/lib/skynet-keys altında. Kurucu servisi kendiliğinden başlatmaz.
- [x] Salt okunur doctor; eksik/yanlış anahtar, Vault şifre çözme, native SDK/binary, dizin ve Docker kontrolü.
  Taşınmış run yolları için dry-run + tutarlı yedek + idempotent relocate aracı.
- [x] UBI 9 Linux x86_64 / glibc 2.34 / Python 3.12.15 içinde **148/148 test**; macOS'ta **148/148**.
  Linux testleri UID 1001, güncel kod salt okunur mount ile çalıştı. systemd-analyze verify geçti.
- [x] Gerçek HTTP sunucusunda login/CSRF, hedef, Vault, kampanya, devre dışı zamanlama ve restart kalıcılığı.
  Restart aynı 0600 anahtarı korudu; doctor mevcut şifreli Vault kaydını doğruladı. Tarama başlatılmadı.
- [x] Linux sunucusundan 12 görünüm × 1366×768 ve 1920×1080; ekran görüntüleri ve DOM ölçümleri kaydedildi.
  Sayfa genelinde yatay taşma ve JS konsol hatası yok. İndirme menüsü İngilizceye tamamlandı.
- [x] Aşağıdaki tarihsel “gövdesiz GET” kusuru kapatıldı: yalnız Caido aracı açıkça tamamlandı dediğinde,
  geçerli Host/başlıkları olan ve gövde beklemeyen istek kabul edilir. Eksik/truncated gövde, Transfer-Encoding,
  belirsiz Content-Length ve kısmi yanıt reddedilir. İki regresyon testi eklendi. Verify sonuç kuralları ve
  classification_version=2 değişmedi; eski inconclusive sonuçlar yeniden yazılmadı. Evidence aynı parser'ı kullanır.
- [ ] Gerçek RHEL sunucusunda systemd boot, SELinux enforcing, Docker sandbox ve izinli hedefle uçtan uca tarama.
  UBI testi bunların yerine geçmez; QA konteynerine host Docker soketi verilmedi, doctor Docker kontrolü atlandı.

Asıl data/anahtar değiştirilmedi; yeni migration, dış hedef taraması, commit veya production deploy yapılmadı.
SKY özelliklerinin aşağıda belirtilen diğer sınırları (browser yalnız metadata vb.) devam ediyor.

## R1–R6 düzeltmeleri — tamamlandı (Codex, 15 Kasım 2026)

Aşağıdaki ilk incelemede bulunan altı kusur düzeltildi.
Ayrıntı: [docs/reviews/2026-11-15-sky-fixes.md](docs/reviews/2026-11-15-sky-fixes.md).

- [x] R1 — Vault ekleme/rotasyonunda timeline cache ve istemci metinleri güncel maskeleme bağlamıyla yenileniyor.
- [x] R2 — Coverage/compare scheme, host ve port ayrımını koruyor; belirsiz origin'ler birleşmiyor.
- [x] R3 — Trafik sayısı ve ajan beyanı Tested yapmıyor; aynı taramanın kabul edilmiş, ilgili kanıtlara bağlı Verify kaydı gerekiyor. Desteklenmeyen test kategorileri partial/unknown.
- [x] R4 — Coverage başlangıç olayına sonradan öğrenilen outcome yazılmıyor.
- [x] R5 — Sırası belirlenemeyen çelişkili oturum sinyalleri Unknown; zaman hassasiyeti ve saat dilimi gözetiliyor.
- [x] R6 — Büyük canlı parti kayıpsız sayfalanıyor; güncellenen olaylar ve filtre dışına çıkan kayıtlar yenileniyor. Restart, geç olaylar ve geçmiş sayfalaması ele alındı.
- [x] 138/138 test geçti; 14 yeni regresyon ilk durumda hataları yakalayıp düzeltmelerle geçti.
- [x] 1366×768 ve 1920×1080 görsel QA; dört etkilenen görünümde yatay taşma/konsol hatası yok.
- [x] Browser canlı QA fikstüründe 600 olayın tamamı geldi, yeni Vault test sırrı otomatik maskelendi;
  ikinci parti ve geçmiş okuma birlikte 1203/1203 kayda ulaştı. Fikstürde Strix/LLM çalışmadı.

Kanıtlar: [docs/qa/2026-11-15-fixes](docs/qa/2026-11-15-fixes).
Yeni migration/production değişikliği/commit yapılmadı. Önceki özelliklerin diğer bilinen sınırları devam ediyor.

## İlk bağımsız inceleme — tarihsel bulgular (Codex, 15 Kasım 2026)

Bu altı bulgunun düzeltmeleri ve son doğrulama yukarıdaki R1–R6 bölümünde kayıtlıdır.

**Aşağıdaki önceki “yedi özellik tamamlandı” kaydı nihai kabul olarak okunmamalı.**
Güncel inceleme: [docs/reviews/2026-11-15-sky-review.md](docs/reviews/2026-11-15-sky-review.md).
124 mevcut test geçti; ek izole senaryolar üç P1 ve üç P2 kusur üretti. Uygulama kodu bu incelemede düzeltilmedi.

- [ ] R1/P1 — Timeline cache, Vault ekleme/rotasyon sonrasında güncel sırları yeniden maskelemiyor.
- [ ] R2/P1 — Coverage kimliği host/port'u atıyor; başka origin'in kanıtı hedefe test atfedebiliyor.
- [ ] R3/P1 — Aynı endpoint'e iki sıradan istek, ilgisiz test kategorisini Tested yapabiliyor.
- [ ] R4/P2 — Coverage'ın güncel outcome'u geçmiş recorded_at olayına taşınıyor; replay geçmişi çarpıtıyor.
- [ ] R5/P2 — Aynı kaynak zamanındaki çelişkili oturum kanıtında request ID kesin durum seçiyor.
- [ ] R6/P2 — 500'den büyük canlı olay partisinin kalanı cursor ilerlemesiyle atlanabiliyor.

Kanıt betiği: `.venv/bin/python docs/reviews/reproduce_sky_issues.py` (yalnız geçici fixture verisi).
Görsel QA: yedi görünüm × 1366×768 ve 1920×1080, sayfa genelinde yatay taşma/konsol hatası görülmedi;
[docs/qa/2026-11-15-review](docs/qa/2026-11-15-review). Tarayıcı görünümü yalnız metadata;
tam canlı görüntü özelliği değildir. Yeni Strix/LLM taraması ve asıl DB migration'ı yapılmadı.

## Yeni kabul edilen geliştirme kapsamı — 15 Kasım 2026

Kullanıcının seçimiyle [docs/FEATURE_BACKLOG.md](docs/FEATURE_BACKLOG.md) eklendi. Yedi özellik aynı gün uygulandı;
ayrıntılı kayıt aşağıdaki **"SKY-01…07 — uygulandı"** bölümünde. İşaret = kabul ölçütleri fikstür testleri ve
yerel kayıtlı gerçek verilerle doğrulandı; yeni bir Strix/LLM taraması bu özellikler için çalıştırılmadı.

- [x] SKY-01 — Tarama karşılaştırması (sürüm/build/commit Skynet'te kayıtlı değil → "Scan comparison" etiketi).
- [x] SKY-02 — Profil × ajan bazında, an'a ve kanıta bağlı oturum sağlığı.
- [x] SKY-03 — Endpoint × rol × test türü kanıta bağlı kapsam matrisi (WSTG v4.2 eşlemesi sezgisel).
- [x] SKY-04 — Talimat merkezi: kabul / bağlamda / uygulama ayrımı, talimattan sonraki ajan aktivitesi.
- [x] SKY-05 — Tarayıcı görünümü: canlı akış yok (Strix desteklemiyor); görüntüler maskelenemediği için gösterilmiyor, yalnız metadata.
- [x] SKY-06 — Ortak zaman çizelgesi ve yalnız kayıtları okuyan replay.
- [x] SKY-07 — Kanıt çalışma alanı: yan yana kayıtlar, maskeli fark, analist rolleri/notları (yalnız ekleme).

Bu dosya ürün kararlarıyla kodda doğrulanmış durumu ayırır. `HANDOFF.md` önceki oturumun notudur;
buradaki sonuçlar kaynak kodu, izole testler ve yerel tarayıcı kontrollerinden gelir.

## Bu oturumda tamamlananlar

- [x] Repository ve son commitler incelendi. `AGENTS.md` bulunmadı. Başlangıçtaki commit edilmemiş değişiklikler korundu.
- [x] Kurulu Strix CLI'da `--target`, `--instruction-file`, `--workspace-file` ve normal çıkış kodları yardım çıktısından doğrulandı.
- [x] Bulgu doğrulaması ayrı bir kuyruk çalışmasıyla ilişkilendirildi; kayıtlar tek transaction içinde oluşturuluyor.
- [x] Doğrulamada LLM, güncel atanmış Vault profilleri, bütçe ve tur sınırı seçimi eklendi.
- [x] Parmak izi / temiz çıkış / HTTP 200 / başarılı ön kontrol tek başına kesin sonuç üretmiyor.
- [x] Yeni bulgu için ilişkili saldırı/kontrol HTTP kayıtları, yeni PoC, kanıt ve Strix `http_exchange_ids` bağlantısı aranıyor.
- [x] Negatif sonuç için tamamlanan test ve ilgili testlerde doğrulanmış oturum gerekiyor. Kanıtlanamayan form girişi `inconclusive`.
- [x] Kuyruktan iptal, başlatma hatası, kesinti ve yeniden başlatma yolları doğrulama kaydını kapatıyor.
- [x] Eski sınıflandırmalar önceki sonuç/gerekçe korunarak yeniden değerlendiriliyor; tarama yeniden başlatılmıyor.
- [x] Orijinal bulgu dosyaları ve occurrence kayıtları korunuyor; giderilme durumu otomatik değişmiyor.
- [x] Güncel ve eski sırların maskelemesi, aynı saniyedeki Vault yenilemeleri ve kısa sırlar için düzeltmeler yapıldı.
- [x] Anahtar kayıpken şifreli kayıtlar varsa yeni anahtar üretimi engellendi.
- [x] Her migration öncesi SQLite backup API ile WAL dahil tutarlı yedek alınıyor; Settings > Data protection altında anahtar konumu ve migration geçmişi gösteriliyor.
- [x] Eksik token/istek/hata/gecikme/araç ölçümlerinin sıfırla karıştırıldığı alanlar düzeltildi.
- [x] Gerçek Strix görev metni, üst ajan ilişkisi, durum ve son araç aktiviteleriyle ajan kartları eklendi.
- [x] Canlı izleme eklendi: mevcut `agents.db` kayıtlarından ajan mesajları ve araç çağrısı/yanıtları, 2 saniyelik artımlı okuma, ajan filtresi, otomatik takip.
- [x] Araç çağrısı ve yanıtı tek açılır kartta birleştirildi; ajan ağacı ve çalışma özetiyle canlı görünüm yeniden tasarlandı.
- [x] Koyu kömür / ölçülü amber tema sabitlendi; görsel kontrol sırasında hizalama, boşluk ve gereksiz scrollbar kusurları düzeltildi.
- [x] 66 izole test geçiyor. API testleri gerçek FastAPI middleware ve rotalarını soket veya tarama işçisi başlatmadan çalıştırıyor.

## Son kontroller

- [x] Son kullanıcı tercihine göre arayüz İngilizceye çevrildi: menüler, formlar, canlı akış, hata/sonuç mesajları ve zamanlama açıklamaları. Europe/Istanbul saat dilimi korunuyor.
- [x] Son İngilizce sürümde 1366×768 ve 1920×1080 ekran görüntüleri alındı ve incelendi; hizalama, boşluk, scrollbar ve erişilebilir ajan seçimi kusurları düzeltildi.
- [x] Son testler (66/66), Python derleme, JavaScript sözdizimi ve diff kontrolleri geçti; README ve bu takip dosyası güncellendi.

## Mevcut özelliklerin doğrulanmış kapsamı

| Alan | Kaynak kodunda durum | Bu oturumdaki doğrulama |
| --- | --- | --- |
| Hedef, kuyruk, iptal, geçmiş, rapor | Mevcut | Kod incelemesi; kuyruk/iptal ve API regresyon testleri |
| Zamanlamalar / Europe/Istanbul | Mevcut | Kod incelemesi; geçmişe dönük/harici plan başlatılmadı |
| OpenRouter ve LiteLLM | İkisi de kalıcı profil; tarama ve zamanlamada seçim mevcut | Kod incelemesi ve profil seçimi API testi; yeni sağlayıcı çağrısı yapılmadı |
| Kampanyalar / Vault | Mevcut | Kod incelemesi, migration ve maskeleme testleri; gerçek kayıtlarla UI |
| Keşif envanteri | Mevcut, kapsamı genişletmez | Tekrarlanan ingest kayıt/sayaç çoğaltmıyor testi; gerçek kayıtlarla UI |
| Telemetri | Mevcut; eksik veri kuralları düzeltildi | Log ayrıştırma ve eksik/sıfır ölçüm testleri; geçmiş gerçek tarama çıktıları |
| Bulgu gruplama | Parmak iziyle aday ilişkilendirme mevcut | Aynı açık olduğunun kanıtı olarak sunulmuyor; orijinal gözlemler korunuyor |
| Doğrula | Kod ve API testleri tamamlandı | Kanıt okuyucu + yaşam döngüsü + API testleri; yeni canlı Strix pentesti henüz çalıştırılmadı |

## Kanıt ve ortam

- Test komutu: `.venv/bin/python -m unittest discover -s tests -v`
- Görseller: [docs/qa/2026-11-15](docs/qa/2026-11-15)
- Görsel QA: önceki yerel test ortamından SQLite backup API ile alınan ayrı kopya; kuyruk, zamanlayıcı, import ve recovery tarama başlatmaları kapalı.
- Yan tarayıcı: `http://127.0.0.1:8790`; ekranda gerçek, tamamlanmış yerel test kayıtları var.
- Asıl `data/` veritabanı ve mevcut anahtar değiştirilmedi. Harici hedeflerde tarama başlatılmadı veya sürdürülmedi.
- Henüz commit veya production dağıtımı yapılmadı.

## Bilinen sınırlar

- Strix talimat ve kanıt sözleşmesine uymazsa sonuç güvenli biçimde `inconclusive` kalır.
- Genel bulgu grupları parmak izi aday gruplarıdır; otomatik semantik eşdeğerlik kanıtı değildir.
- Form-login oturum sürekliliği mevcut verilerle güvenilir doğrulanamıyorsa negatif sonuç üretilmez.
- Canlı izleme Strix'in diske yazdığı görünür olayları gösterir; kendi ajan orkestrasyonunu veya ilerleme yüzdesi üretmez.
- Nessus, AppScan, Burp MCP, Swarm/IP havuzu, AD ve Shells kapsam dışı kalır.

## Son QA sonucu

- 8 ana sayfa iki viewport ölçüsünde kontrol edildi; canlı akış, ajan filtresi, ajan kartları, telemetri,
  bulgu ve Verify/Re-verify penceresi ayrıca görüntülendi.
- 1366×768 ve 1920×1080 ölçümleri tarayıcı DOM'undan doğrulandı. Yatay taşma ve JavaScript hatası görülmedi.
- Bulgulardaki geçmiş doğrulamaların eski kurallarla üretilmiş olumlu/negatif iddiaları yeni kanıt şartlarını
  sağlamadığı için `inconclusive` olarak yeniden değerlendirildi. Önceki sonuç/gerekçe DB'de korundu.
- Son ekranlar `.jpg`, otomatik ölçüm özeti `browser-checks.json`, test çıktısı `tests.txt` dosyalarıdır.
- Kayıtlı hedef/profil adları ve eski Strix rapor metinleri kullanıcı verisidir; uygulama dilini değiştirirken bu kayıtlar yeniden yazılmadı.

## Ayrı kabul çalışması gerektirenler

- [ ] Yeni kanıt sözleşmesinin model tarafından gerçek Strix çalışmasında tamamlandığını izinli yerel hedefte doğrulamak.
  Bu oturum yeni bir pentest veya sağlayıcı çağrısı başlatmadı. Mevcut sonuçları incelemek yeniden çalıştırma olarak sunulmadı.
- [ ] Production'a alma ve asıl kurulumda migration uygulama. Bu oturumda yapılmadı.

## Canlı ajana prompt gönderme — uygulandı (Claude, 15 Kasım 2026)

Codex'in araştırması ve `.strix-runtime/` kurulumu üzerine devam edildi ([docs/CLAUDE_HANDOFF.md](docs/CLAUDE_HANDOFF.md)).

Araştırmada önerilen yol değiştirildi, çünkü kurulu Strix 1.7.0 kaynağında şunlar görüldü:
headless modda `coordinator.send(from="user")` çalışan ajanı kesmeden `waiting` yapıyor (tur metinle biterse
ajanın döngüsü erken dönüyor, root için `finish_scan` olmadan bitiş), bütçe duraklatmasını açabiliyor ve
gelen kutusu yalnızca `wait_for_agents` ile okunuyor. Bunun yerine openai-agents 0.19.4'ün genel
`RunConfig.call_model_input_filter` parametresi kullanıldı.

- [x] Spike: sahte model + gerçek SDK Runner ile filtreye eklenen mesajın aynı çalışmanın sonraki çağrılarında
  görünüp görünmediği ve oturuma doğru sırada yazılıp yazılmadığı ölçüldü.
- [x] `skynet/strix_bridge.py`: resmi `strix.interface.main` aynen çalışır; `run_strix_scan(coordinator=)` ve
  `RunConfig` filtresi bağlanır, sürüm/imza uymazsa hiçbir şey değiştirilmez. 127.0.0.1 + geçici port +
  bearer token + Host denetimi, 0600 manifest/durum dosyası (içeriksiz), request_id tekilleştirme, ajan başına
  5 bekleyen mesaj, 4000 karakter sınırı. Bilinmeyen/bitmiş ajan, bütçe duraklatması ve kapanışta reddeder.
  Ajan bitince veya tarama kapanınca bekleyen mesaj `expired` olur; `delivered` iddiası üretilmez.
- [x] `skynet/control.py` + runner: runtime sürümü binary sürümüne eşitse köprüyle, değilse binary ile başlatma
  (`scans.control_mode/control_note`). Manifest PID/protokol/izin/sahiplik doğrulaması, sabit host, yönlendirmesiz
  `http.client`. Durumlar yalnızca ileri gider; izleme döngüsünde ve bitişte senkronize edilir.
- [x] Migration 4: `agent_messages` (içerik Vault anahtarıyla şifreli), öncesinde mevcut backup yolu.
- [x] API: `GET/POST /api/scans/{id}/messages`, `POST .../messages/{mid}/recheck` (aynı request_id ile sorar,
  ikinci kopya üretmez). Oturum + CSRF; tarama silinince mesaj kayıtları da silinir. Arayüz maskelemesi uygulanır.
- [x] Live activity composer (İngilizce): ajan seçimi, ağaçtan seçim senkronu, taslak/odak korunur, ⌘/Ctrl+Enter,
  çift tıklama/yeniden denemede aynı request_id, `Unconfirmed` için Check again, gönderilmiş mesaj geçmişi.
  Köprüsüz/bitmiş taramada gerekçe gösterilir. Settings'te açma/kapama ve uygunluk durumu.
- [x] Mevcut hata düzeltildi: `_cleanup_runtime(1)` `scan_1*` ile scan 12'nin dosyalarını da siliyordu.
- [x] Filtre hata korumalı: o ajana mesaj yoksa girdi aynen geçer; oturum yazımı vb. hata verirse model çağrısı
  değişmeden sürer ve mesaj `queued` kalır (asla `delivered` denmez). Zaman aşımı sonrası uç kaybolursa kayıt
  sahte `rejected` olmaz, `Unconfirmed` kalır.
- [x] **Varsayılan kapalı (opt-in).** Settings > Agent messaging açılmadıkça taramalar eskisi gibi binary ile başlar.
  Gerçek bir köprülü tarama kabul testini geçene kadar zamanlanmış/CI/doğrulama taramalarının motor yolu değişmez.
- [x] Testler 87/87 (`.venv/bin/python -m unittest discover -s tests`). Yeni 21 testin 3'ü
  `.strix-runtime` ile gerçek `AgentCoordinator`, gerçek Strix ajan oturumu ve gerçek SDK Runner'ı (betikli model,
  sağlayıcı/Docker yok) çalıştırır: durum `running` kalır, native mailbox boş kalır, mesaj aynı çalışmanın her
  sonraki çağrısında tam bir kez ve araç çıktısından hemen sonra görünür, oturuma bir kez yazılır, ikinci
  çalışmada yalnızca geçmişten gelir; `install()` gerçek modüllere bağlanır, manifest 0600 ve çıkışta silinir;
  `strix_bridge.py --version` resmi CLI'ya geçer. Runtime yoksa bu testler görünür biçimde atlanır.
- [x] Görsel QA (1366×768, 1920×1080): Codex QA veritabanının scratchpad'de ayrı bir backup kopyası; asıl `data/`
  ve Codex QA kopyasına dokunulmadı. Çalışan tarama görünümü için **QA fikstürü** kullanıldı: tamamlanmış yerel
  scan17 çıktısının kopyası, gerçek `AgentCoordinator` bu kopyadan restore edildi, gerçek köprü kanalı ve kontrol
  ucu; birkaç ajan running/waiting yapıldı ve 6 sn'de bir köprünün gerçek filtresi çağrıldı. Arayüzden
  gönderilen mesaj Queued → In agent context oldu ve kopya agents.db'ye yazıldı. Ekranlar:
  [docs/qa/2026-11-15-messaging](docs/qa/2026-11-15-messaging) (tarayıcı aracının küçültülmüş 800 px
  yakalamaları; ölçümler tam çözünürlükte DOM'dan alındı). Yatay taşma ve konsol hatası yok.
  1366×768'de composer kaydırmadan görünür; sayfanın dikey kaydırması sağ ajan panelinden gelir ve değişiklik
  öncesinde de 849 px idi.

### Gerçek tarama kabul testi — geçti (kullanıcı onayıyla, 15 Kasım 2026)

Ortam: Codex QA veritabanının scratchpad'deki ayrı backup kopyası, yalnızca kuyruk işçisi açık (zamanlayıcı,
içe aktarma, backfill, recovery kapalı), Settings'te messaging açık. Hedef yalnızca izinli yerel test uygulaması
`127.0.0.1:8899`; OpenRouter deepseek-v4.1-flash, quick mod. Asıl `data/` ve anahtar kullanılmadı.

- [x] **Tarama #21** ($0.40 bütçe sınırı): `control_mode=bridge`, log'da `operator messaging attached
  (strix-agent 1.7.0)`, manifest oluştu.
  - Çalışan *Recon & Surface Mapping* ajanına arayüzden mesaj: kabulden 2 sn sonra `In agent context`. Gerçek
    `agents.db`'de işaret bir `function_call_output`'un hemen ardında (öğe 65); ajanın sonraki turu
    "Noted the operator instruction…" diyor ve `agent_finish` özetine istenen ifadeyi ekledi.
  - `wait_for_agents` içinde bekleyen root ajana mesaj: önce `Queued`, root uyanınca `In agent context`.
    Recon'dan gelen native ajan mesajı aynı adımda geldi (native mesajlaşma bozulmadı). Final raporun 19. satırı:
    "Operator note SKYNET-E2E-ROOT received."
  - `finish_scan` → çıkış kodu 0, `completed`, rapor yazıldı; manifest ve runtime dosyaları silindi; sandbox
    konteyneri temizlendi. Maliyet $0.392. Bazı alt ajanlar bilinçli düşük bütçe yüzünden Strix'in bütçe
    rezervinde durdu (native davranış); bu çalışmada bulgu raporlanmadı.
- [x] **Tarama #22** ($0.15 sınır): root ajana mesaj gönderilip hemen Stop. SIGINT → Strix "interrupted by the
  user" → sandbox 2 sn içinde kapandı → `cancelled`. Mesaj `Not delivered` ("The scan ended before the agent's
  next model call"); oturumda gerçekten yok. Manifest/runtime dosyaları silindi, konteyner kalmadı. Maliyet $0.012.
- Ekran: [docs/qa/2026-11-15-messaging/e2e-real-scan-history-1366.jpg](docs/qa/2026-11-15-messaging/e2e-real-scan-history-1366.jpg).
- Kalan: köprü runtime bağımlılıkları PyInstaller binary'sininkilerle birebir aynı olmayabilir; bu iki gerçek
  çalışmada sorun görülmedi. Messaging hâlâ varsayılan kapalı (Settings'ten açılır).
- [ ] Production'a alma ve asıl kurulumda migration 4. Yapılmadı; commit yapılmadı.

### Bilinen sınır

- Strix bir ajan çalışması kalıcı olmayan bir hatayla çökerse `_salvage_stream_to_session` oturumu
  "çalışma öncesi + SDK akışı" ile yeniden yazar. Köprünün çalışma sırasında oturuma eklediği mesaj bu
  yeniden yazımda düşebilir. Ajan o noktada failed/crashed olur; mesaj çökmeden önceki çağrılarda bağlamdaydı,
  ama `--resume` geçmişinde görünmeyebilir. Bağlam sıkıştırması (`maybe_compact`) modeli doğrudan çağırır,
  filtreden geçmez; özetleyiciye mesaj enjekte edilmez.

## SKY-01…07 — uygulandı (Claude, 15 Kasım 2026)

Kaynak: [docs/FEATURE_BACKLOG.md](docs/FEATURE_BACKLOG.md). Önce güncel kod, testler ve yerel gerçek çalışma
çıktıları incelendi; mevcut mesajlaşma, Verify ve envanter yeniden yazılmadı. Strix orkestrasyonuna dokunulmadı.

### Ortak altyapı ve doğrulanan gerçekler

- `skynet/evidence.py`: ajanların Caido araçlarıyla kaydettiği istek/yanıtlar için tek salt-okur çıkarıcı.
  `view_request` tam istek/yanıt verir; `list_requests` yalnız metadata; `repeat_request`/`send_request` yeni
  Caido kimliği döndürmez (Strix 1.7 kaynağında doğrulandı), kanıt kaydı sayılmaz. Kimlikler çalışma adıyla kapsanır.
- **Gerçek veride bulunan iki tuzak:** (1) Strix oturumu yeniden yazarken `agents.db` satır id'leri ve
  `created_at` değişir (dış bir geçmiş çalışmada 240 öğe aynı saniyede) → olay kimlikleri call_id / içerik özetiyle
  kurulur, "yeniden yazılmış" zamanlar kullanılmaz. (2) Caido `created_at` saat dilimsiz ve UTC değil (yerel
  çalışmada 21:41:41 GMT için 00:41:41) → dilim aynı çalışmadaki GMT `Date` başlıklarından türetilir, türetilemezse
  Caido zamanı "bilinmiyor" sayılır.
- Caido'nun gövdesiz GET isteği görünümünde boş satır ayırıcısı yok. Çıkarıcı, araç "tam" dediği (has_more=false)
  mesajı kabul eder. `verify._http` aynı nedenle bu istekleri reddediyor; Verify sınıflandırması değiştirilmedi
  (aşağıda "Kalanlar").
- Migration 5 (mevcut backup yolu ile): `analyst_notes`, `analyst_note_revisions` (şifreli), `evidence_labels`,
  `occurrence_reviews` (hepsi yalnız ekleme), `scans.auth_snapshot` (taramaya başlarken profil bağlama HMAC
  özetleri + sır olmayan metadata; API'de gösterilmez).
- `activity.read` düzeltmesi: `view_image` çıktısındaki base64 görüntü daha önce metin olarak canlı akışa
  kırpılarak veriliyordu; artık yer tutucu metinle değiştiriliyor.

### SKY-02 — Oturum sağlığı (`skynet/session_health.py`, sekme "Session health")

1. Davranış: her profil için ajan bazında Session verified / Session lost / Unknown / Not applicable, kanıt zamanı +
   zaman kaynağı (Caido isteği / ajan oturumuna kayıt), kanıt kaydına açılan "Open". Ön kontrol ayrı satırda,
   "tarama sırasındaki oturumun kanıtı değildir" etiketiyle. Profil düzeyinde tek genel hüküm verilmez.
2. Kanıt yolu: tam istek/yanıt; istek profilin kimlik bilgisini taşıyor mu → HMAC özet karşılaştırması
   (`verify._binding`). Kimlik işaretçisi + beklenen durum = verified; 401 veya login'e yönlendirme = lost;
   403 = yetki reddi (oturum kaybı değil); işaretçisiz 200 = kanıt yok. Eski taramalarda profil sırrı tarama
   başlangıcından beri değişmediyse güncel profil kullanılır, değiştiyse "karşılaştırılamaz". Form-login →
   Unknown (ajanın aldığı oturum çerezi bilinmez). **Ajan atfı = yanıtı Caido'da görüntüleyen ajan**; Caido
   paylaşımlı olduğu için isteği gönderen ajan ayrıca bilinmez. Periyodik aktif kontrol eklenmedi.
3. Testler (fikstür): ön kontrol başarılı → sonra 401 → a1 lost, a2 verified; 403/işaretçisiz 200; login
   yönlendirmesi; başka token; form-login/anonim; eksik sayfa; form-login negatif Verify → inconclusive; çıktıda sır
   ve özet yok. Gerçek kayıt: tarama 17'de kök ajan verified (/api/me), doğrulayıcı ajan Unknown (gerekçeli).

### SKY-03 — Kanıtlı kapsam (`skynet/coverage_matrix.py`, sekme "Coverage")

1. Davranış: endpoint × rol × test türü tablosu; filtreler ve durum sayaçları; hücre ayrıntısında Skynet gerekçesi,
   kaynak coverage kaydı (değiştirilmemiş metin), kanıt kayıtları, ajanlar, zaman. "Tested" güvenli demek değildir.
2. Kurallar: Tested = coverage kaydı testi bildiriyor **ve** o endpoint+rol için en az iki farklı tam istek/yanıt;
   tek kayıt veya yalnız liste metadatası → Partially tested; hepsi 401/403 → Access blocked; kaydı/isteği olmayan
   gözlenen endpoint → Not tested (kayıt yokluğunun gönderilmediğini kanıtlamadığı yazılı); not_applicable →
   ajanın gerekçesiyle; geri kalan → Unknown. Rol = Vault profil referansı (sır yok) / anonymous / unattributed.
   Test türü = OWASP WSTG v4.2 kategori kimliği, serbest metin risk alanından **sezgisel** eşleme; uyumluluk iddiası yok.
3. Testler: durumların kanıt gerektirmesi, her Tested hücresinin bu çalışmanın tam kayıtlarına gitmesi, coverage.json
   özetinin değişmemesi, iddia tek başına/tek istek ≠ Tested, anonim trafik, eksik dosya. Gerçek kayıt: tarama 17.

### SKY-01 — Tarama karşılaştırması (`skynet/compare.py`, hedef sayfası → "Compare scans")

1. Davranış: referans ve karşılaştırma taraması seçilir; bulgular (yeni gözlem / tekrar görülen / bu çalışmada
   gözlenmeyen), endpoint'ler (yeni / gözlenmeyen / "Not tested in this run"), kapsam hücresi değişimleri ve
   `inventory.run_diff` özeti. Uyarılar: tamamlanmamış/iptal tarama, eksik coverage, mod/profil/hedef/talimat farkı,
   doğrulama çalışması, aynı Strix çalışması. Skor yok. Sürüm/build/commit kaydı olmadığı açıkça yazılır.
2. Okuma anında hesaplanır, hiçbir şey kalıcı yazılmaz; giderilme durumu değişmez. Eşleşme varsayılan olarak
   "Fingerprint candidate"; iki occurrence da analistçe onaylandıysa "Match confirmed by analyst". Farklı hedef reddedilir.
   Kapsam araması yöntem bazında (OPTIONS satırı GET'in durumunu almaz).
3. Testler: bulunmayan bulgu `open` kalır; iptal + eksik coverage + mod/profil farkı uyarıları; anahtarlarda skor yok;
   iki kez yeniden içe aktarma → aynı çıktı ve aynı satır sayıları; analist onayı; "Not tested in this run";
   yöntem bazlı arama; farklı hedef. Gerçek kayıt: 17 ↔ 21 (21'in coverage kaydı eksik uyarısı, bulgu Open kalır).

### SKY-04 — Talimat merkezi (sekme "Instructions"; `control.py` genişletildi)

1. Davranış: ajan filtresi; her talimatta Sent / Accepted by Strix / Added to agent context zamanları;
   "Accepted, ended before reaching context" ayrı; bağlamdaki mesajda "Application not confirmed". "Agent activity
   after this instruction" o ajanın oturumunda talimat işaretinden sonraki görünür aktiviteyi gösterir; zaman
   sırasının neden-sonuç kanıtı olmadığı yazılı. Gönderim hâlâ Live activity composer'ından (değiştirilmedi).
2. İşaret konumu her seferinde ajanın kendi oturumunda `[Operator message via Skynet console | id=…]` aranarak
   bulunur (yeniden yazmaya dayanıklı). Messaging kapalı / motor uyumsuz / tarama bitmiş gerekçesi gösterilir.
3. Testler: işaret yalnız hedef ajanda bulunur, sonraki aktivite yalnız o ajandan ve işaretten sonra; kabul edilip
   biten ≠ bağlamda; teslim edilmemiş mesajda aktivite yok; geçmişte sır maskeli. Eski 21 mesajlaşma testi geçiyor.
   Gerçek kayıt: tarama 21'in iki gerçek operatör mesajı (işaretler gerçek agents.db'de bulundu).

### SKY-05 — Tarayıcı görünümü (`skynet/browser.py`, sekme "Browser")

1. Davranış: ajan seçimi; durum No screenshot recorded / Latest screenshot (≤120 sn, tarama sürerken) / Stale /
   Recorded; son kayıt metadata'sı (ajan, oturuma kayıt zamanı, sandbox dosya yolu, boyut). Ajan değişince eski
   görünüm hemen temizlenir; geç gelen eski yanıt atılır. Bağlantı koparsa "Connection lost" gösterilir.
2. Strix 1.7 kaynağı: canlı akış/CDP/ekran görüntüsü API'si yok; görüntü yalnız ajan `view_image` ile yüklerse
   `agents.db`'de saklanır, eskileri Strix siler. **Görüntü pikselleri hiçbir yerde sunulmuyor**: metin maskeleyici
   görüntüdeki kimlik bilgisini/kişisel veriyi bulamaz. "Live" etiketi hiçbir zaman gösterilmez.
3. Testler: görüntü baytları browser/activity/timeline çıktısında yok; a1'in görüntüsü a2'ye verilmez; tazelik
   eşikleri; okuma hiçbir runner/control/HTTP çağrısı yapmaz. Yerel gerçek çalışmalarda görüntü kaydı yok.

### SKY-06 — Zaman çizelgesi ve replay (`skynet/timeline.py`, sekme "Timeline")

1. Davranış: tür/ajan/metin filtreleri, 200'lük sayfalama, canlı takip (anahtarla birleştirme, geç gelen eski
   zamanlı olay için yeniden okuma), replay (oynat/duraklat, adım, hız, konum; tüm geçmiş en fazla 5000 olay).
   Replay konumu değişince hiçbir API isteği atılmaz (tarayıcıda ölçüldü).
2. Kaynaklar: ajan mesajları, araç çağrı/sonuçları, Caido istekleri, oturum kanıtı, operatör talimatı aşamaları,
   bulgular, coverage kayıtları, tarama yaşam döngüsü. Her olayda kaynak zamanı türü; zamansızlar "Timestamp
   unavailable" ile sonda; aynı zamanlılar işaretli. Yeniden yazma tespiti sezgisel (oturumda aynı saniyede ≥25 öğe).
3. Testler: oturum yeniden yazılınca aynı anahtarlar ve zaman "yok"; tekrar okuma çoğaltmaz; sıra dışı/aynı zaman/
   zamansız; sayfalama çakışmasız; ajan filtresi; maskeleme; okuma/replay hiçbir şey çalıştırmaz; katı maskelemenin
   anahtarları birleştirmemesi (QA'da yakalanan hata).

### SKY-07 — Kanıt çalışma alanı (`skynet/workspace.py`, `#/findings/{id}`; Verification panelinden açılır)

1. Davranış: bağlam = occurrence veya doğrulama çalışması; sol/sağ seçilebilir kayıtlar (istek+yanıt, tamlık,
   görüntüleyen ajan, Caido zamanı), maskeli fark (istek/yanıt), maskeli indirme, rol atama (attack/control/
   context — "Assigned by analyst"), occurrence eşleşmesini onayla/reddet, revizyon geçmişli analist notları.
2. Rol kaynağı her zaman yazılı: Strix bağlantısı (rol vermez, Skynet eşleştirmez) / doğrulama değerlendirmesi
   (ajan beyanı) / analist. Eksik kayıt, eksik klasör, eksik bulgu "Evidence gap" olarak gösterilir. Notlar şifreli,
   gösterimde maskeli; HTML metin olarak gösterilir. Bulguya bağlı ekran görüntüsü kaynağı yok.
3. Testler: Strix bağlantıları eşleştirilmez, eksik kimlik açık; not/rol/inceleme sonrası occurrence, grup,
   doğrulama satırları ve çalışma dosyalarının özetleri aynı; not revizyonları ve şifreleme; fark/indirme maskeli,
   başka çalışmaya erişim yok; yeniden içe aktarma notları korur ve çoğaltmaz; yeni doğrulama eskisinin bağlamını
   değiştirmez; eksik klasör; API CSRF. Gerçek kayıt: bulgu 1 (`vuln-0001`, 4 bağlı tam kayıt, token maskeli).

### Testler, görsel QA, ortam

- `.venv/bin/python -m unittest discover -s tests` → **124/124** (87 önceki + 37 yeni `tests/test_sky.py`;
  hepsi fikstür). Python derleme, `node --check` (app.js, sky.js) ve `git diff --check` geçti.
- Görsel QA: 7 görünüm × 1366×768 ve 1920×1080, yatay taşma yok, JS hatası yok:
  [docs/qa/2026-11-15-sky](docs/qa/2026-11-15-sky) (`browser-checks.json` düzeltilen 9 kusuru listeler).
  Ortam: önceki Claude QA veritabanının scratchpad'de SQLite backup API ile alınmış kopyası, kuyruk/zamanlayıcı/
  içe aktarma/kurtarma kapalı sunucu (127.0.0.1:8792). Asıl `data/` ve önceki QA kopyalarına dokunulmadı.
  Yeni Strix taraması veya LLM çağrısı yapılmadı; dış hedeflerin geçmişi yalnız yapı (satır sayısı/biçim) için okundu.
- Commit yapılmadı.

### Danışman incelemesi sonrası düzeltmeler (aynı gün)

- SKY-03: kayıtlar artık yalnız ait oldukları coverage kaydına sayılır (kaydı yazan ajan, yazılmadan önce görüntülemiş
  olmalı; `reported` kayıtta anılan bulgunun `http_exchange_ids`). Birleşen hücrede her kaydın kendi değerlendirmesi
  görünür ("Tested · 1 of 2 records"). Gerçek veride path-alias iddiası artık "Partially tested".
- SKY-02: sinyal zamanı Caido → yanıt `Date` başlığı → görüntüleme zamanı; çelişen sinyaller yalnız görüntüleme
  zamanıyla sıralanıyorsa durum Unknown. Tablo başlığı "Recorded by".
- Canlı yol **QA fikstürüyle** çalıştırıldı (scratchpad'de tarama 17 çıktısının kopyası, `running` tarama #23, kopya
  agents.db'ye satır ekleme; Strix/LLM yok): kök ajan 5 sn içinde Session lost oldu, diğer ajan etkilenmedi; zaman
  çizelgesinde canlı ve eski zamanlı geç olay tam bir kez geldi (Skynet ilk görülme zamanı ile `seen_after`);
  Browser Stale → Latest screenshot (sentetik 1×1 PNG, DOM'da görüntü verisi yok). Ekran: `live-session-lost-1366.jpg`.
- Yeniden yazma koruması evidence/browser'a da uygulandı. Performans (en büyük yerel geçmiş, 8316 olay): zaman
  çizelgesi ilk oluşturma 2.0 sn, sonraki sayfa ~1 ms; pahalı canlı oluşturmalar seyreltilir, replay DOM'u ≤500 satır.
- `auth_snapshot` süreç başlatılmadan önce hesaplanıyor; talimat aktivitesinde "Load more". Konsolda hata yok.

### Kalanlar ve sınırlar

- [x] **Sonraki QA'da kapatıldı:** `verify._http` gövdesiz Caido isteklerini reddediyordu. Güncel düzeltme
      yukarıdaki RHEL/QA bölümünde; Verify sonuç kuralları/sürümü değiştirilmeden parser onarıldı.
- [ ] Bu özelliklerle yeni bir gerçek Strix taraması (`auth_snapshot` ile başlayan ilk tarama) çalıştırılmadı;
      canlı görünümler yalnız QA fikstürüyle doğrulandı. Karşılaştırmadaki kapsam değişimi satırları kanıta bağlanmıyor.
- [ ] Ekran görüntülerini göstermek için görsel maskeleme veya kullanıcının açıkça kabul ettiği bir erişim politikası yok.
- Sürüm/build/commit alanı eklenmedi (kaynak yok). WSTG eşlemesi ve yeniden yazma tespiti sezgiseldir.
- Production'a alma ve asıl kurulumda migration 5 yapılmadı.


## Çoklu kullanıcı, roller, denetim kaydı ve yönetim raporu — uygulandı (Claude, 16 Kasım 2026)

**Kapsam:** Kullanıcının seçtiği iki özellik: (7) kullanıcılar/roller/audit log, (8) yönetim raporu (PDF).

- **Migration 6** (`users`, `audit_log`): mevcut `settings.admin_password_hash` yerleşik admin satırına taşınır, ayar
  silinir. Gerçek `data/skynet.db` bu oturumda v6'ya taşındı; yedek `data/backups/skynet-pre-v6-*.db`.
- **Roller** viewer / analyst / admin. `skynet/audit.py` `RULES` tek politika tablosu: middleware her istekte rolü
  denetler, listede olmayan değiştirici rota admin'e düşer. Oturum çerezi kullanıcı kimliği + şifre parmak izi taşır;
  rol/etkinlik her istekte DB'den okunur. Yerleşik `SKYNET_USER` hesabı arayüzden değiştirilemez; son admin korunur.
- Notlar, etiketler, korelasyon incelemeleri ve ajan mesajlarının yazarı artık oturumdaki kullanıcı (önceden sabit `admin`).
- **Audit log:** her değiştirici API çağrısı middleware'de yazılır (gövde asla); işleyiciler sır içermeyen özet ekler.
  Giriş/başarısız giriş, zamanlayıcı (`scheduler`) ve CI token (`ci-token`) aktörleri, rapor görüntüleme kaydedilir.
- **Arayüz:** kenar çubuğunda kullanıcı + rol, admin için "Audit log" sayfası (kullanıcı/eylem/arama filtresi, sayfalama),
  Settings > Users (ekle, rol, şifre sıfırla, devre dışı bırak, sil) ve "Your account". Yetkisiz düğmeler gizlenir
  (`LABEL_NEEDS`); 403 yanıtı kullanıcıya gereken rolü söyler.
- **Rapor:** `skynet/report.py` + `#/targets/{id}/report`, `#/campaigns/{id}/report`. Kullanıcı kararıyla PDF tarayıcıda
  "Save as PDF" ile üretilir (yeni bağımlılık yok). SLA verisi olmadığı için "son tarihe uyum" yerine açık kalma
  süresi ve düzeltme süresi gösterilir; eksik taramalar eğilimde işaretlidir.
- **Düzeltilen yan hata:** `app.js` ile `sky.js` aynı global adı (`ROLE_TR`) tanımlayınca `sky.js` yüklenmiyordu; ad
  değiştirildi ve iki dosyada ortak üst düzey ad kalmadığı kontrol edildi.

### Testler ve doğrulama

- `.venv/bin/python -m unittest discover -s tests` → **174/174** (23 yeni, `tests/test_users_audit.py`): her değiştirici
  rotanın açık kuralı olması, viewer'ın tüm değiştirici rotalarda / analyst'in admin rotalarında 403 alması, oturum
  iptali (şifre sıfırlama, devre dışı bırakma), rol değişikliğinin açık oturuma uygulanması, audit içeriği (gövde yok),
  CI token aktörü, migration 6 veri taşıması, rapor içeriği/maskeleme/viewer erişimi, kayıtlı tüm zaman biçimlerinin
  (Strix ISO+offset, `... UTC`, saat dilimsiz) rapor yaşı hesabında okunması.
- Tarayıcı: Users ve Audit log 1366×768 ve 1920×1080'de (admin); viewer görünümü yalnız 1366×768'de (nav, gizli
  düğmeler, Settings yalnız hesap, 403 mesajı) geçici `qa-analyst`/`qa-viewer` hesaplarıyla. Hesaplar QA sonunda
  silindi; audit kayıtları (eklemeli) duruyor. Son yüklemede `sky.js` yüklü, Timeline sekmesi çalışıyor.
- Rapor görsel kontrolü **QA fikstürüyle** yapıldı (geçici veri klasörü, 8793 portu; gerçek `data/`'ya veri eklenmedi);
  yazdırma düzeni `@media print` kuralları ekranda etkinleştirilip 186 mm genişlikte ölçüldü: hedef raporu 14 bulgulu,
  uzun başlıklı fikstürde 262 mm (A4 yazdırılabilir ~273 mm) → tek sayfa; kampanya raporu 2 hedefle 289 mm → hedef
  tablosu büyüdükçe 2. sayfaya taşar (bölümler bölünmez). Açık bulgu listesi en önemli 6 ile sınırlı, kalanı sayıyla
  belirtilir. Gerçek veride rapor boş durumlarıyla açıldı. Gerçek yazdırma penceresi/PDF dosyası otomasyonla üretilmedi.

### Kalanlar

- [ ] Kapsam (coverage) hücre çipleri gerçek trafik içeren bir çalışmayla görsel olarak denenmedi (fikstürde hücre yok).
- [ ] "Download PDF" ile gerçek bir PDF kullanıcı tarafından bir kez üretilip kontrol edilmeli.
- Rol ayrımı bir tasarım kararıdır: analyst hedef/zamanlama/kampanya düzenleyebilir; viewer talimat geçmişini ve
  kanıtı okuyabilir. İstenirse `audit.RULES` tek yerden değiştirilir.
- [ ] Audit log için saklama/temizleme politikası yok (eklemeli, sınırsız büyür).
- [ ] Yeniden kullanıcı adı değiştirme, SSO/LDAP ve MFA yok. SLA (son tarih) özelliği seçilmedi.
- Commit yapılmadı.

## 17 Kasım 2026 — Rapor geliştirmesi ve genişletilmiş uygulama incelemesi

Kullanıcının rapor oluşturmayı iyileştirme isteğiyle özet/ayrıntılı rapor, tüm bulguları içeren register,
current-scope eki, deterministik yönetici özeti ve Markdown indirme eklendi. Sonraki isteği üzerine inceleme
raporun dışına, uygulamanın veri/yetki/yürütme ve frontend yollarına genişletildi.

- Ayrıntılı kayıt: [uygulama kodu incelemesi](docs/reviews/2026-11-17-application-code-review.md), CR-01…17.
- 48 uygulama/kurulum kaynak dosyası, 13.919 satırlık envanter; üçüncü taraf Strix/venv kaynağı kapsam dışı.
- Somut düzeltmeler: log ve HTTP kanıtında kesmeden önce maskeleme; resume geçmişi ve bozuk bağlamda 503;
  envanter/telemetri/mesaj metadata'sında read-time maskeleme; etkin portu koruyan scope; eksik/bozuk bulgu
  çıktısında CI pass vermeme; spawn sonrası kayıt hatasında süreç sonlandırma; kampanya filtresini limitten
  önce uygulama; uzun endpoint kimlikleri; strict LLM/CI decrypt; bozuk cookie/timezone; frontend geç yanıtları;
  clipped kanıt/diff/export etiketleri ve talimat öncesine dönemeyen activity cursor.
- Son doğrulama: **246 Python testi + 2 Node testi geçti**; compileall, üç JS syntax ve diff-check temiz.
  Yerel bridge/SIEM testleri için sandbox socket izni kullanıldı. Yeni 22 uygulama inceleme regresyonu ve
  ilk turdaki 10 rapor regresyonu var. Mevcut ResourceWarning mesajları testleri bozmadı.
- Görsel QA: geçici DB/anahtar, 12 sentetik bulgu; 1366×768 ve 1920×1080, Admin ve Viewer. Rapor/campaign/scan
  Details kontrolü, gerçek Markdown indirme; yatay taşma ve browser warning/error yok.
  [Ekranlar ve kontrol notları](docs/qa/2026-11-17-code-review/README.md).
- Kalanlar: gerçek PDF sayfa sayfa kabulü; fingerprint veri modelinde scheme/port ayrımı için ayrı migration;
  saklama politikası ve gerçek RHEL host kabulü. Tam güvenlik denetimi/hatasızlık iddiası yok.
- Asıl veri/anahtar/yedekler değiştirilmedi. Normal lifespan/worker/scheduler, dış hedef veya yeni Strix/LLM
  taraması başlatılmadı. Commit/push/deploy ve asıl servis restart'ı yapılmadı.

## 18 Kasım 2026 — OpenCode Go ve otomatik Strix yolları

Kullanıcı OpenCode Go abonelik anahtarını eklemek ve runtime yollarının otomatik seçilip manuel override
edilebilmesini istedi.

- OpenCode Go ayrı LLM provider olarak eklendi; resmî Go OpenAI adresi, `openai/<model>`, varsayılan chat
  completions; her taramada kendi User-Agent'i ve sabit `x-opencode-session`, resume'da orijinal oturum.
- Settings formu, katalog testi/model önerileri ve tarama provider etiketleri güncellendi. Katalog kontrolü
  anahtar doğrulaması/çıkarım/kota kontrolü olarak sunulmuyor; Go hatasında Zen/PAYG'ye geçiş yok.
- Anahtar şifreli saklanıyor; provider değişiminde eski anahtar tekrar kullanılmıyor. `oc_sk_` pattern
  maskelemesi ve launch öncesinde gerçek LLM anahtarının şifreli maskeleme snapshot'ına eklenmesi var.
- Boş runtime ayarları artık her okumada yeniden çözülüyor: ortam override'ı → paketlenmiş executable →
  kullanıcı kurulumu → PATH. Workdir ortam override'ı veya yazılabilir home; home uygun değilse data/work.
- Settings yolları ayrı ayrı manuel override edilebiliyor; otomatik aday/kaynak görünür, “Use automatic
  paths → Save” boş değerlere döndürüyor. Eski kayıtlı yollar korunuyor, sessiz fallback yok. Çalışan tarama
  varken workdir değişimi engelleniyor. Doctor aynı salt okunur resolver'ı kullanıyor.
- **265 Python + 2 Node testi geçti** (19 yeni regresyon); compileall/JS syntax/diff-check temiz.
  Native Strix settings ve header aktarımı gerçek runtime içinde doğrulandı; ücretli üretim isteği yok.
- 1366×768 ve 1920×1080 izole tarayıcı QA: Go katalog/kayıt/düzenleme/provider değişimi, otomatik yol
  kayıt/manüel override/reload/reset. [Ekranlar, yöntem ve sınırlar](docs/qa/2026-11-18-opencode-go/README.md).
- Gerçek Go anahtarı/kota/çıkarım kabulü henüz denenmedi. Asıl DB, anahtarlar, mevcut servis ve taramalar
  değiştirilmedi; migration/deploy/commit/push yok. Geçici QA sunucusu durduruldu.

### Kullanıcının anahtarıyla Go bağlantı testi

Kullanıcı profili kaydedip katalogdan 31 model gördükten sonra gerçek test istedi. Kaydedilen Go profili ve
`glm-5.3-flash` ile yalnız sabit bir bağlantı mesajı/zararsız araç şeması gönderildi; hedef veya tarama içeriği
gönderilmedi. Tek istek, 512 çıktı token sınırı, kendi User-Agent'i ve ayrı sabit test oturumu kullanıldı.

- HTTP **200**, streaming **3 olay**, `skynet_connection_test({"status":"ok"})` araç çağrısı doğrulandı.
- Süre **0,70 sn**; sağlayıcı **189 giriş + 14 çıkış = 203 token**, `billing_source: go`, bu istekte `cost: 0`
  bildirdi. Kalan kota sayısal olarak ölçülmedi; sonraki isteklerin ücret/limit garantisi değildir.
- Anahtar çıktı/loga yazılmadı, profil değiştirilmedi; Strix/pentest başlatılmadı.

## 18 Kasım 2026 — Otomatik model katalogları ve seçim ekranı

- OpenCode Go / OpenRouter / LiteLLM bağlantılarına otomatik model yükleme, arama, listeden seçim,
  yenileme, manuel model kimliği ve Settings satırına **Change model** eklendi.
- Kayıtlı bağlantı açılınca, yeni bağlantı alanlarından çıkılınca katalog yenileniyor. Tek model/boş seçim
  otomatik doluyor; çoklu modeller veya mevcut/özel seçim rastgele değiştirilmiyor. Kaydetme açık bir eylem.
- Ayrı admin model kataloğu endpoint'i çıkarım yapmıyor. OpenRouter public katalog için key/decrypt
  istemiyor. Otomatik sorguda saklı credential başka adres/provider'a taşınmıyor. Geç response/error ve
  kapanan dialog sonuçları atılıyor; katalogda olmayan model uyarısı ve manuel giriş korunuyor.
- Model önizlemesinde OpenRouter `openai/...` vendor öneki yanlış silinmiyor. Tarama launch snapshot'ı
  artık kuyruğa girdikten sonra değişen profilin gerçekten kullanılan model/provider/adını kaydediyor.
- **273 Python + 7 Node** geçti; 8 yeni backend + 5 yeni frontend regresyonu, compileall/syntax/diff temiz.
  [İki viewport, üç sağlayıcı ve seçim/kayıt kanıtları](docs/qa/2026-11-18-model-picker/README.md).
- Gerçek profil modelleri/anahtarlar değiştirilmedi; yeni çıkarım/tarama/migration yok. İzole QA kapatıldı;
  kullanıcı testi için localhost:8787 preview güncel kodla, lifespan/worker/scheduler kapalı yeniden açıldı.
  Commit/push yok.
- Yan panelde gerçek Go seçicisi 31 modelle açıldı; `glm-5.3-flash` korundu, gerçek profile Save yapılmadı.
