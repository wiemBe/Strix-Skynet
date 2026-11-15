# Skynet: 4 özellik geliştirmesi — devir notu (güncel: 2026-11-15)

İstek: Pentest kampanyaları, Vault (kimlik profilleri), kalıcı keşif envanteri, tarama telemetrisi.
Mevcut hedef/tarama/zamanlama/ajan yapıları yeniden yazılmadan genişletildi. Chat, Swarm, AD, Shells veya yeni
motor eklenmedi.

## Durum: TAMAMLANDI (henüz commit edilmedi)

Tüm backend + frontend yazıldı, gerçek veriye karşı doğrulandı, 16 birim testi geçiyor, README güncellendi.
Kalan tek iş: canlı uçtan uca tarama (aşağıda "Devam eden" bölümü) ve commit. **Hiçbir şey commit edilmedi.**

### Git durumu
- Değişen: `skynet/config.py`, `crypto.py`, `db.py`, `runner.py`, `scheduler.py`, `main.py`, `targets.py`,
  `static/app.js`, `static/style.css`, `README.md`
- Yeni: `skynet/campaigns.py`, `vault.py`, `findings_store.py`, `inventory.py`, `redact.py`, `scope.py`,
  `telemetry.py`, `tests/test_features.py`
- Branch: `main` (commit öncesi yeni branch açılmalı).

## Neler yapıldı (modül modül)

**config.py** — `SECRET_KEY_FILE` artık `~/.config/skynet/secret.key` (veri klasörü dışında; `SKYNET_SECRET_KEY_FILE`
ile değişir). Eski konum `LEGACY_SECRET_KEY_FILE` = `data/secret.key`.

**crypto.py** — anahtar ilk açılışta veri klasörü dışına taşınır (kopyala→doğrula→sil), asla yeniden üretilmez.
`key_status()`, `decrypt_strict()`, `DecryptError`, türetilmiş vault alt anahtarı (`vault_encrypt`/`vault_decrypt`).

**db.py** — `schema_migrations` + `migrate()` + migration öncesi `data/backups/` yedeği. `MIGRATION_1`: campaigns,
campaign_targets, auth_profiles, auth_profile_targets, finding_groups, finding_occurrences, assets,
asset_observations, run_ingest, scan_telemetry tabloları + scans/schedules'e yeni sütunlar. Veri migration'ı
`_migrate_inline_target_auth`: hedefteki satır içi kimliği bir profile taşır, profili hedefe + o hedefin
zamanlamalarına bağlar, **ve geçmiş taramalara redact_enc anlık görüntüsü yazar** (profil sonradan değişse de eski
plaintext maskeli kalır). `decrypt_strict` kullanır (anahtar uyuşmazsa migration durur, kimliği silmez).
`SCAN_SELECT`'e campaign JOIN eklendi.

**redact.py** — değer bazlı (sır + url/base64 varyantları) ve desen bazlı (strict: Authorization/Cookie/api-key,
LLM anahtarları) maskeleme.

**scope.py** — URL/host normalizasyonu, `host.docker.internal` eşlemesi, kapsam etiketi (in/out/unknown). Kapsamı
asla genişletmez.

**vault.py** — profil türleri anonymous/credentials/header/cookie. `resolve()` (atama+okunabilirlik zorlar,
`AuthError`), `render()` (sırlar `--workspace-file` ile `/workspace/skynet_auth/`'a, talimatta sır yok), `verify()`
(Skynet ön kontrolü, yalnızca header/cookie + kapsam içi URL), `scan_redactor()`/`global_redactor()`, `save()`,
`public()`.

**findings_store.py** — parmak izi host+yöntem+normalize endpoint+CWE. Gözlemler run bazında (resume iki kez
saymaz). Giderilme durumu elle; "giderildikten sonra görüldü" bayrağı. `groups_for_scans`, `summary`, `occurrences`.

**inventory.py** — proxy (agents.db Caido kayıtları), finding, coverage, threat_model kaynakları; kanıt düzeyi
observed/reported. Teknoloji yalnızca yanıt başlıklarından. `ingest`, `run_diff`, `assets_for`, `observations`,
`summary_for`, `source_sig`.

**telemetry.py** — `strix.log` + `run.json` + `agents.db` artımlı okuma. **Önemli:** gerçek log satırlarından
yazıldı, handoff parafrazından değil. Kaynaklar: `strix.llm.request_log: llm_request ... outcome= cost= duration_ms=
ttft_ms= attempt=` (yeni Strix), `openai.agents: Calling LLM` (her sürüm, deneme sayısı), retry için
`strix.core.execution: ... replaying turn (attempt n/5 ...): <ErrorClass>` (RateLimitError→rate_limit,
TimeoutError→timeout, diğer→connection). Araçlar agents.db function_call'dan (session_id=agent_id). Log saati yerel
naive → `astimezone` ile UTC (SKYNET_TIMEZONE değil, sistem yereli). Maliyet: providers doluysa provider, yoksa
LiteLLM tahmini, cost=0 ise "hesaplayamadı". Eksik veri null (sıfır değil).

**runner.py** — `enqueue(campaign_id, auth_profile_ids)` + `vault.resolve`. `_start`: tekrar resolve (kuyrukta değişmiş
olabilir), `vault.render` → `--workspace-file`, redact_enc anlık görüntü, `_auth_precheck`. `_fail` runtime dosyalarını
siler. `_monitor` ~10sn'de telemetri toplar. `finalize` → `_ingest_run` (telemetri + findings + inventory + run_ingest,
try/except, `_ingest_lock` ile kronolojik). `backfill_existing()` (açılışta arka planda, source_sig ile idempotent).

**scheduler.py** — `_fire` campaign_id + auth_profile_ids aktarır; `AuthError` "error" olayı olur.

**campaigns.py** (yeni) — CRUD, arşiv (silme yalnızca arşivlide, sadece bağlantı koparır), hedef atama, bulgu özeti.

**main.py** — yeni uçlar: campaigns, auth-profiles (+assign/verify, silme/atama-kaldırma bağlı zamanlamayı duraklatır),
inventory, telemetry, findings (grup + remediation PATCH). Maskeleme: `/log` (satır hizalı + strict), `/download/*`
(raw FileResponse yerine redakte Response), rapor/bulgular/yönetici özeti (md.render öncesi). Hedef formundan satır içi
auth kaldırıldı (`_target_payload` auth_type='none' zorlar; `targets.instruction_text`'ten auth bloğu silindi).
Ayarlar'da key_status + migrations. lifespan'de `runner.start_backfill()`.

**static/app.js + style.css** — yeni menüler Kampanyalar/Envanter/Kimlik profilleri; scan detayında Telemetri sekmesi;
Ajanlar tablosu kullanım+araç sayılarıyla birleşti; scan/schedule formlarında kampanya + kimlik profili seçici;
hedef formundan auth alanları kaldırıldı; poll hatasında toast yerine bağlantı durumu bandı. Kullanıcı geri bildirimiyle
5 düzeltme: auth ikonu (anahtar "auth"), select ok kırpılması (custom chevron), checkbox-metin boşluğu
(`.field label` display:block çakışması), TUI içe aktarma bandı kaldırıldı, bulgu özeti taşması (facts hücresinde wrap).

**tests/test_features.py** — 16 test: scope (split/norm_path/label/host_map), fingerprint, redact (değer+varyant+strict),
telemetry (_classify/_parse_log/_cost/_local_to_utc), migration (satır içi auth → profil + redact_enc snapshot).
Çalıştır: `python -m unittest discover -s tests` (geçici veri klasörü; gerçek data/'ya dokunmaz).

## Doğrulanmış bulgular (gerçek veriye karşı)
- Migration gerçek DB kopyasında çalıştı: "Lokal test hedefi" satır içi `credentials` kimliği "Lokal test hedefi –
  kullanıcı" profiline taşındı, hedefe atandı, şifre çözülebilir, redact_enc snapshot yazıldı.
- 14 gerçek run hatasız ingest edildi; proxy kullanan testapp run'ında 8 varlık (1 host, 1 servis, 6 endpoint),
  kapsam=in, kanıt=observed; resume (aynı run_name) idempotent.
- Telemetri gerçek run'larda: 3287 araç çağrısı/39 ajan, retry sınıflandırma (timeout/connection), provider maliyeti,
  yerel→UTC saat dönüşümü doğru.
- `--workspace-file PATH[:DEST]` `strix --help` ile doğrulandı; vault.render çıktısıyla birebir uyumlu.
- Frontend tüm görünümler tarayıcıda QA edildi (8788): kampanya listesi, envanter (kapsam pill'leri), kimlik
  profilleri (migrate edilen profil), telemetri sekmesi (14 istek/18 araç/maliyet).
- Auth profili uçtan uca: header profili oluştur→doğrula (gerçek testapp isteği, "tester" bulundu)→sil (bağlı
  zamanlama duraklatıldı). Sır profil JSON'unda asla geri gönderilmedi.

## Devam eden iş (bu oturumda başlatıldı)
Canlı uçtan uca tarama: dev 8788 üzerinden testapp (127.0.0.1:8899) hedefine, **header kimlik profili (Bearer token)
#3** ve kampanya #1 ile **quick** tarama **#17** başlatıldı (max_budget 0.30). Amaç: `--workspace-file` ile token
sızıntısı olmadığını (run.json/coverage/strix.log/agents.db/instruction'da token yok), maskelemeyi, telemetri +
findings + inventory ingest'i ve cancel→resume'u doğrulamak. Sonuç kontrol edilmeli.

## Ortam / geliştirme kurulumu
- Gerçek Skynet **8787**'de ESKİ kodla çalışıyor. Gerçek `data/` ve `~/.config/skynet/secret.key`'e dokunulmadı.
- Dev kopya (yeniden başlatmada silinebilir, bu oturumun scratchpad'inde):
  `/private/tmp/claude-501/-Users-efe--claude-spares-spare-VFGqrU/e4d99011-e897-45be-b2f6-601d0491720f/scratchpad/`
  - `dev-data/` (gerçek DB yedeğinden seed, migration uygulandı), `dev-keys/secret.key`, `dev-workdir/strix_runs/`
  - `testapp/app.py` + `creds.json` (Bearer: `tk-user-...`, `tk-admin-...`), `python app.py 8899` ile çalışır.
- Dev sunucu: `SKYNET_DATA=…/dev-data SKYNET_SECRET_KEY_FILE=…/dev-keys/secret.key SKYNET_PASSWORD=devpass123
  SKYNET_PORT=8788` ile uvicorn. Giriş admin/devpass123. Cookie jar `/tmp/sk.txt`, CSRF başlığı `x-requested-with: skynet`
  (curl'de başlık `: ` boşluğuyla, yoksa uvicorn 400 "Invalid HTTP request").
- venv: `./.venv`. Testler ve dev sunucu buradan.
- Gerçek tarama yalnızca 127.0.0.1 testapp'e. Harici run'lar (aktifbank, nkolay, pavo, sigortayeri, upt) salt okunur
  backfill dışında asla başlatılmaz/devam ettirilmez.

## Commit öncesi
- Yeni branch aç, commit et. Attribution satırı: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Gerçek ortama almadan önce: gerçek DB otomatik migrate olur (açılışta backup alınır) ve anahtar yeni konuma taşınır.
