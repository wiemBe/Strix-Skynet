# Claude'a devir — Skynet

> **Güncel değil:** Bu devirdeki "son özellik henüz uygulanmadı" notu artık geçerli değil. Canlı ajana mesaj
> özelliği 15 Kasım 2026'da farklı bir teslim yoluyla uygulandı; durum ve kalan doğrulamalar için
> [PROGRESS.md](../PROGRESS.md) içindeki "Canlı ajana prompt gönderme" bölümüne bakın.

15 Kasım 2026 · `/Users/efe/Documents/Strix` · Europe/Istanbul

## Buradan başla

Kullanıcı son olarak “senin limit azaldı Claude'a vereceğim ona göre ayarla” dedi.
Bu dosya işi başka asistana devretmek için yazıldı. **Son özellik henüz uygulanmadı.**
Commit / deploy yapılmadı. Mevcut çalışma ağacını koru; reset/checkout ile değişiklikleri silme.
Bu repo içinde çalışma talimatı olan `AGENTS.md` bulunmadı; `.strix-runtime/` bağımlılıklarının
içindeki aynı adlı dosyalar Skynet repository talimatı değil.

İlk okunacaklar: bu dosya, `PROGRESS.md`, `README.md`, ilgili kaynak ve testler.
Kökteki `HANDOFF.md` geri kalanı eski oturum notudur; güncel tamamlanma kanıtı değildir.

## Kullanıcı istekleri ve geçerli kararlar

- Skynet, Strix üstünde pentest yönetim GUI'si. Strix ajan orkestrasyonunu yeniden yazma.
- Hedefler, anlık/zamanlanmış taramalar, kuyruk/iptal/geçmiş/rapor; kalıcı OpenRouter ve LiteLLM profilleri.
- Kampanyalar, güncel Vault profilleri, gerçek keşif envanteri, gerçek telemetri ve bulgu yaşam döngüsü.
- Son dil tercihi **arayüzün tamamen İngilizce olması**. İlk Türkçe UI kararını geçersiz kılıyor.
  Kullanıcıyla Türkçe konuşulabilir. Kayıtlı hedef/profil adları ve eski raporlar kullanıcı verisidir;
  UI çevirisi diye kayıtları yeniden yazma.
- Kömür tonları ve ölçülü amber; sol navigasyon, net hiyerarşi; gradient/neon/scanline/dekoratif grafik/sahte veri yok.
- Gerçek ajan görevleri, hiyerarşi ve aktiviteler; “canlı yayın gibi” akış istendi ve eklendi.
- Yapılanları `PROGRESS.md` içinde takip et.
- **Sıradaki iş:** “canlı taramada herhangi bir agenta prompt yazma özelliği”.
- Tarayıcıda **1366×768 ve 1920×1080** ekran görüntüsü al, incele, kusurları düzelt, yeniden kontrol et.
- Yalnızca izinli yerel hedeflerde test et. Eski dış hedeflerin geçmişini okumak onları yeniden çalıştırma izni değildir.
- Kapsam keşifle genişlemez. Eksik ölçüm sıfır değildir. Parmak izi tek başına açık eşdeğerliği kanıtı değildir.
- Sırlar snapshot/log/rapora sızmamalı. Migration öncesi WAL dahil tutarlı yedek; mevcut anahtar korunmalı.
- Nessus, AppScan, Burp MCP, Swarm/IP havuzu, AD, Shells kapsam dışı.

## Doğrulanmış mevcut durum

HEAD: `8fbfd73` (öncesi `f59186a`, `52d44da`). Uncommitted kaynak değişiklikleri mevcut.
Son devir kontrolünde `.venv/bin/python -m unittest discover -s tests -v` → **66/66 geçti**.
Önceki kontrol: Python derleme, JS sözdizimi ve `git diff --check` geçti.
Bu 66 test **yeni ajan mesajlaşması testleri değildir**.

Tamamlanan başlıca kodlar:

- `skynet/verify.py`: ayrı odaklı doğrulama taraması, güncel Vault ve LLM profili seçimi;
  muhafazakâr kanıt sınıflandırması. Orijinal bulgu/occurrence korunur; otomatik “giderildi” yok.
- Sonuç sözleşmesi `SKYNET_VERIFICATION_V1:` işaretli gerçek `exec_command` çıktısı, ilişkili
  saldırı/kontrol HTTP kayıtları, yeni kanıt/PoC ve Strix `http_exchange_ids` ister.
  Temiz çıkış, fingerprint, HTTP 200 veya ön kontrol başarıları tek başına yeterli değil.
  Güncel header/cookie kanıtları keyed HMAC bağlamıyla kontrol edilir; kanıtlanamayan form-login → inconclusive.
- `runner.py`: scan+verification atomik oluşturma; başlatma/iptal/hata/recovery yolları;
  doğrulama ilişkilerini korumak için ilgili resume/delete kısıtları.
- DB migration 2/3: finding_verifications, `verification_evidence`, classification_version,
  önceki sonuç/gerekçe. Eski sonuçlar kanıt kurallarıyla yeniden değerlendirilir; pentest yeniden başlatılmaz.
- Anahtar kayıpken şifreli veri varsa yeni anahtar üretilmez. Migration SQLite backup API kullanır.
- Maskeleme: kısa sırlar, güncel/eski profil sırları, aynı saniye rotasyon cache invalidation;
  orijinal dosyalar silinse de bulgu metadata sırlarının maskelenmesi.
- Eksik telemetri null; tekrar ingest kayıt/sayaç çoğaltmıyor.
- `skynet/activity.py`: `.state/agents.db` üzerinden artımlı salt okunur akış;
  görünür assistant `output_text`, araç çağrısı/sonucu; reasoning/user prompt/binary/provider metadata dışarı verilmez.
  Maskeleme truncation öncesi; call_id ile çağrı/yanıt eşleşmesi.
- `GET /api/scans/{sid}/activity?after=-1&agent_id=...&limit=60`.
- `runs.py`: `.state/agents.json` görev metni, parent, durum ve son araçlar.
- İngilizce UI, 2 sn poll, ajan filtresi, otomatik takip, max 180 kart, ajan ağacı,
  açılır araç çağrısı/yanıt çifti, Settings > Data protection.

Sınır: yeni doğrulama sözleşmesiyle gerçek yeni Strix+LLM pentesti bu oturumda çalıştırılmadı.
Mevcut testler ve geçmiş yerel verilerin incelemesi bu kabul çalışmasının yerine geçmez.

## Son özellik: ajan mesajlaşması araştırması

**Uygulama kodu / API / migration / composer henüz yok.** Yalnızca araştırma ve ayrı runtime kurulumu yapıldı.

Kurulu binary: `/Users/efe/.strix/bin/strix`, sürüm **1.7.0**, PyInstaller / Python 3.12.
CLI `--target`, `--instruction-file`, `--workspace-file`, `--non-interactive` desteği doğrulandı.
Mevcut `skynet/runner.py:_launch` bu binary'yi headless ve stdin DEVNULL ile çalıştırıyor.

Kurulu binary içindeki kod incelendi; aynı sürüm resmi PyPI wheel kaynakları da alındı.
Şu ayrı proje ortamı kuruldu ve `pip check` geçti:

```sh
.strix-runtime/bin/python -m pip show strix-agent  # Version: 1.7.0
.strix-runtime/bin/python -m pip check           # No broken requirements found
```

`.strix-runtime/` gitignore'a eklendi. Var olan runner henüz onu kullanmıyor; global Strix binary değiştirilmedi.
Venv yerel Python 3.12 runtime'ına bağlıdır; başka makineye kopyalamak yerine yeniden kurulmalı.
Python 3.12 burada: `/Users/efe/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3`.
Repo test ortamı `.venv` ise Python 3.15; iki ortamı birbirine karıştırma.

İnceleme kanıtı, kurulu native kaynak yolları:

- `.strix-runtime/lib/python3.12/site-packages/strix/interface/viewer/server.py:560`
  `serve(..., steer_handler=None)` docstring'i: callback yalnızca canlı TUI sürecindeki launcher'dan gelir.
  Standalone `strix view` steering sunmaz. `GET /api/capabilities`, `POST /api/agents/steer` var;
  bunların bulunması Skynet headless taramalarına erişim olduğu anlamına gelmez.
- `.../strix/core/runner.py:180`: native `run_strix_scan(..., coordinator: AgentCoordinator | None, ...)`.
- `.../strix/interface/cli.py`: `run_cli` mevcut native runner'ı coordinator vermeden çağırıyor.
- `.../strix/core/agents.py:409`: `reachability(agent_id)` ve `send` metotları.
  `await coordinator.send(aid, {"from": "user", "content": message, "type": "instruction"})`
  gerçek mailbox'a koyup wake ediyor; uygun durumda native stream interrupt ediyor.
  True sonucu **kabul / inbox'a kuyruklama** demek; okundu/uygulandı kanıtı değil.
  Native user-message davranışı budget pause'u açabilir; adapter bunu sessizce tetiklememeli.

Geçici inceleme dosyaları: `/private/tmp/skynet-strix-inspect/`.
Wheel `wheels/strix_agent-1.7.0-py3-none-macosx_11_0_arm64.whl`, açılmış kaynak `source/strix/`.
Bunlar geçici; kalıcı native kaynak yukarıdaki venv'de var.

## Önerilen devam yolu — uygulanmış kabul etme

Native Strix orkestrasyonunu koruyan ince bir headless launcher/kontrol köprüsü düşünüldü.
Bu tasarım henüz uygulama ve runtime testleriyle doğrulanmadı; gerekirse daha iyi native entegrasyon seç.

1. `skynet/strix_bridge.py` gibi stdlib kontrol katmanı, resmi native CLI main'ini çalıştırsın;
   CLI'nın import ettiği `run_strix_scan` çağrısına native `AgentCoordinator` verip orijinal fonksiyona delege etsin.
   Bütçe, araçlar, raporlar, sinyaller, cleanup, kapsam, config ve native exit davranışı korunsun.
   Python runtime/binary sürüm uyumunu kontrol et; sessizce farklı motor sürümüne geçme.
   Uygun değilse eski CLI taramaları çalışabilsin, mesaj özelliği dürüstçe unavailable görünsün.
2. Sadece 127.0.0.1 ephemeral port + rastgele bearer token; native event loop'a coroutine ilet.
   Private manifest (0600) runtime altında scan_id/pid/protocol/port/token içersin; loglara/token API'ye sızmasın.
   URL/PID/scan doğrulansın; keyfi URL/redirect çağırma. Süreç kapanınca endpoint/manifest temizlensin.
   Native coordinator state'i running/waiting olan gerçek ajana ilet; bitmiş/olmayan ajana reddet.
   Budget-paused ajanı mesaj gönderildi diye otomatik sürdürme veya bütçe sınırını değiştirme.
3. Skynet authenticated + CSRF korumalı POST ve redakte geçmiş/capabilities GET ekle.
   Audit DB migration'ı öncesinde mevcut backup yolunu kullan; promptları şifreli sakla.
   request_id ile idempotence; aynı ID farklı içerik conflict. Ağ timeout'unda kabul edilmiş olabilir:
   unknown durumunu göster, otomatik yeniden gönderme. Bridge içinde de tekrarları engelle.
   İptal/scan bitişiyle yarışları ve Skynet restart'ını düşün. Sahte disk mailbox yazma.
4. Live activity panelinde ajan seçimi + İngilizce composer + açık gönderme durumu ekle.
   2 sn poll textarea/focus/draft'ı silmesin; gönderimde tekrar tıklama ve retry çift mesaj üretmesin.
   “Accepted by Strix” gibi doğrulanabilen durum kullan; “Read/Executed” iddiası üretme.
   Eski bridge'siz çalışan taramalarda ve geçmişte disabled gerekçe göster.
   Kullanıcı promptu gönderirken sırları Vault üzerinden yönetmesini teşvik et;
   özel promptlar mevcut maskeleme kurallarıyla UI/audit/loglarda korunmalı.
5. Native coordinator mailbox/wake entegrasyonu, auth/CSRF, yanlış ajan, terminal/budget state,
   eski manifest, idempotence, timeout belirsizliği, şifreleme/maskeleme ve iptal yarışlarını test et.
   Gerçek mesajın hedef native coordinator'a ulaştığını test etmeden “çalışıyor” deme.
6. İki viewport görsel QA, güncel ekran görüntüleri ve PROGRESS/README güncellemesi.

## İzole QA ortamı

- Önceki QA sunucusu: `http://127.0.0.1:8790` (çalışıyor olduğunu yeniden kontrol et).
- Script: `/private/tmp/skynet-codex-qa/serve.py`.
- Veri: `/private/tmp/skynet-codex-qa/data`; ayrı anahtar: aynı kökte `secret.key`.
- Sadece QA login: `admin` / `qa-local-password`.
- Script lifespan'ı yalnız db.init/auth.bootstrap/verification geçmiş değerlendirmesi yapıyor;
  queue/scheduler/backfill/import veya native scan recovery başlatmıyor.
- Başlatma: `.venv/bin/python /private/tmp/skynet-codex-qa/serve.py`.
  Socket için sandbox izni gerekebilir. Asıl servisi bunun yerine yanlışlıkla başlatma.
- Yerel hedef geçmişi: target 1 `http://127.0.0.1:8899`; scan17 yerel IDOR geçmişi,
  scan18/19 eski doğrulamalar. Yeni kanıt kurallarında eski olumlu/negatif iddialar inconclusive;
  önceki sonuçlar korunuyor. Diğer dış geçmişleri başlatma/sürdürme.
- Geçmiş yerel testapp kaynağı:
  `/private/tmp/claude-501/-Users-efe--claude-spares-spare-VFGqrU/e4d99011-e897-45be-b2f6-601d0491720f/scratchpad/testapp/app.py`.
  Yanında sır içeren `creds.json` var; değerlerini çıktı/loga basma. 127.0.0.1:8899 dinliyor mu kontrol et.
- Asıl repo `data/` DB ve mevcut anahtar bu çalışmada migrate edilmedi/değiştirilmedi.
  Eski 8787 kurulumunun süreç durumunu varsayma.
- Görsel kanıtlar: `docs/qa/2026-11-15/` (28 JPG, browser-checks.json, tests.txt).
  Son QA'da ölçülen iki viewport'ta yatay taşma ve sayfa JS hatası yoktu.
  Ajan mesaj composer'ı henüz bu ekranlarda yok.

## Güvenli devam kontrolleri

```sh
git status --short
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q skynet tests
node --check skynet/static/app.js
git diff --check
```

Tamamlanmış özellikleri yeniden yazma. Yeni çalışma gerçek kanıtla doğrulanınca takip dosyasını güncelle;
bu devirdeki önerileri uygulanmış gerçek gibi raporlama. Kullanıcı onayı olmadan commit/deploy gerekmez.
