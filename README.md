# Skynet

Skynet, uygulamaları production'a çıkmadan önce ve sonrasında düzenli aralıklarla pentestten geçirmek için
kullanılan web tabanlı yönetim arayüzüdür. Pentest motoru olarak makinede kurulu **[Strix](https://github.com/usestrix/strix)**
CLI'ını kullanır; Strix'i yeniden yazmaz, yalnızca taramaları başlatır, izler, zamanlar ve sonuçlarını gösterir.

- Hedef yönetimi: uygulama, adres, ortam (development / test / staging / production), kapsam içi/dışı
- **Kampanyalar:** birden çok hedefi, taramayı ve zamanlamayı tek angajman altında toplama; tekilleştirilmiş bulgu özeti
- **Kimlik profilleri (vault):** yeniden kullanılabilir kimlik doğrulama (anonim / kullanıcı+şifre / başlık / çerez); sırlar şifreli saklanır ve taramaya yalnızca sandbox dosyası olarak verilir, talimata yazılmaz
- **Keşif envanteri:** taramalarda bulunan host, servis, uç nokta ve teknolojiler; kanıt düzeyi (gözlemlendi / ajan bildirdi), kapsam etiketi ve tarama arası değişim
- **Tarama telemetrisi:** model çağrısı, yeniden deneme (oran limiti/zaman aşımı/bağlantı), gecikme, maliyet kaynağı, token ve ajan başına araç kullanımı
- Anlık tarama, kuyruk, canlı log ve ajan durumu, güvenli durdurma (alt süreçler ve sandbox konteyneri dahil)
- Zamanlama: tek seferlik, günlük, haftalık, saat aralıklı ve cron; duraklat / etkinleştir / düzenle / sil
- Tarama geçmişi, tekilleştirilmiş bulgular (giderilme durumu), Strix raporları, SARIF/CSV/JSON/Markdown indirme
- LLM bağlantı profilleri: OpenRouter ve kurum içi LiteLLM, kod değişikliği olmadan geçiş
- Prod öncesi CI kullanımı için token korumalı API (bulgu eşiği: pass/fail)

Tüm Strix çıktıları (log, rapor, bulgu, yönetici özeti, indirmeler) gösterilmeden önce kimlik profili sırlarına
ve bilinen gizli desenlere karşı maskelenir.

## Kurulum

Gereksinimler: Python 3.10+, Docker (Strix sandbox'ı için çalışır durumda), Strix CLI (`~/.strix/bin/strix`).

```bash
cp .env.example .env      # gerekirse düzenleyin
./run.sh                  # http://127.0.0.1:8787
```

`run.sh` ilk çalıştırmada `.venv` oluşturur ve `requirements.txt` bağımlılıklarını kurar.

**Giriş:** `.env` içinde `SKYNET_PASSWORD` boşsa ilk açılışta rastgele bir şifre üretilir ve
`data/admin_password.txt` dosyasına (0600) yazılır. Kullanıcı adı varsayılan olarak `admin`'dir. Şifre
Ayarlar > Yönetici şifresi bölümünden değiştirilebilir.

**İlk açılış:** `~/.strix/cli-config.json` içinde OpenRouter ayarı varsa otomatik olarak şifreli bir
"OpenRouter" LLM profiline dönüştürülür. Daha önce Strix TUI ile yapılmış taramalar `strix_runs/` klasöründen
içe aktarılır.

## Yapılandırma

Süreç düzeyindeki ayarlar `.env` / ortam değişkenleriyle verilir (tamamı için `.env.example`):

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SKYNET_HOST`, `SKYNET_PORT` | `127.0.0.1`, `8787` | Ağa açarken TLS'li bir reverse proxy arkasında çalıştırın |
| `SKYNET_USER`, `SKYNET_PASSWORD` | `admin`, (üretilir) | Giriş bilgileri |
| `SKYNET_SECRET_KEY` | — | Gizli değerlerin şifreleme anahtarı (Fernet); dosya yerine doğrudan verilebilir |
| `SKYNET_SECRET_KEY_FILE` | `~/.config/skynet/secret.key` | Şifreleme anahtarı dosyası (bilerek `SKYNET_DATA` **dışında**) |
| `SKYNET_COOKIE_SECURE` | `0` | HTTPS arkasında `1` yapın |
| `SKYNET_TIMEZONE` | `Europe/Istanbul` | Zamanlamaların varsayılan saat dilimi |
| `SKYNET_DATA` | `./data` | SQLite veritabanı, süreç logları, geçici çalışma dosyaları |
| `SKYNET_STRIX_BIN`, `SKYNET_STRIX_WORKDIR` | `~/.strix/bin/strix`, `~` | İlk açılış varsayılanları |

Strix binary yolu, çalışma klasörü, eşzamanlı tarama limiti, Strix telemetrisi ve webhook adresi
**Ayarlar** sayfasından yönetilir.

## LLM bağlantıları: OpenRouter ve LiteLLM

Skynet ayrı bir LLM katmanı kurmaz. Seçilen bağlantı profili, Strix'in kendi
[yapılandırma değişkenlerine](https://docs.strix.ai/advanced/configuration) çevrilir ve her tarama için
geçici bir `--config` dosyasıyla (0600, tarama bitince silinir) verilir:

| Profil alanı | Strix değişkeni |
|---|---|
| Model | `STRIX_LLM` (OpenRouter: `openrouter/<model>`, LiteLLM: `openai/<model>`) |
| API anahtarı | `LLM_API_KEY` |
| Base URL | `LLM_API_BASE` |
| API tipi | `STRIX_API_TYPE` (gateway yalnızca chat completions destekliyorsa `chat_completions`) |
| Reasoning effort | `STRIX_REASONING_EFFORT` |
| Özel CA | `SSL_CERT_FILE` |

**Kurum içine geçiş:** Ayarlar > LLM bağlantıları > Bağlantı ekle → Sağlayıcı "LiteLLM", base URL
`http://litellm.kurum.local:4000`, LiteLLM virtual key ve gateway'deki model adı → **Bağlantıyı test et**
(model listesi gelir) → **Varsayılan yap**. Kod değişikliği gerekmez; OpenRouter profili kullanılabilir kalır.

Güvenlik kuralları:
- API anahtarları veritabanında şifreli saklanır, tarayıcıya hiçbir zaman gönderilmez, loglara yazılmaz.
- Her tarama ve zamanlama, kaydedildiği bağlantı profilini kullanır. Profil hata verirse **başka profile otomatik geçilmez**.
- Skynet'in kendi ortamındaki `OPENAI_API_KEY`, `LLM_API_BASE` gibi değişkenler Strix sürecine aktarılmaz; böylece veriler
  yanlışlıkla başka bir sağlayıcıya gitmez.
- Strix telemetrisi (`STRIX_TELEMETRY`) varsayılan olarak **kapalı** başlatılır (Strix'in kendi varsayılanı açıktır).

## Kampanyalar, kimlik profilleri, envanter ve telemetri

- **Kampanyalar** yalnızca gruplamadır: hedefleri, taramaları ve zamanlamaları bir angajman altında toplar ve
  tekilleştirilmiş bulgu özetini gösterir. Taramanın nasıl çalıştığını değiştirmez. Kampanya silme yalnızca arşivlenmiş
  kampanyada mümkündür ve sadece bağlantıları koparır; taramalar, bulgular ve zamanlamalar korunur.
- **Kimlik profilleri** hedeflere atanır; bir tarama yalnızca atandığı profilleri kullanabilir. Profil silinir veya bir
  hedeften kaldırılırsa onu kullanan zamanlamalar otomatik duraklatılır ve bir olay kaydı yazılır (sessizce kimlik
  doğrulamasız çalışmaz). Sırlar türetilmiş bir anahtarla ayrıca şifrelenir; her taramaya başlarken kullanılan değerler
  şifreli bir anlık görüntü olarak saklanır, böylece profil sonradan değişse bile eski taramalardaki maskeleme bozulmaz.
- **Bulgular** host + yöntem + normalize uç nokta + CWE parmak iziyle tekilleştirilir. Her görülme kendi taramasına bağlı
  kalır (devam ettirilen tarama iki kez saymaz). Giderilme durumu (açık / giderildi / kabul edildi / hatalı pozitif) elle
  işaretlenir; "giderildi" bir bulgu sonraki taramada yine görülürse sessizce yeniden açılmaz, işaretlenir.
- **Envanter** yalnızca Strix'in gerçekten kaydettiğinden oluşur: Caido proxy kayıtları ve bulgular "gözlemlendi",
  coverage/threat-model etiketleri "ajan bildirdi" düzeyindedir. Teknoloji yalnızca yanıt başlıklarından çıkarılır.
  Keşfedilen hiçbir şey hedefin kapsamını değiştirmez; kapsam etiketi yalnızca okuma anında hesaplanır.
- **Telemetri** `strix.log` ve `run.json`'dan artımlı okunur. Tamamlanan istek `run.json`'dan, deneme sayısı ve yeniden
  denemeler (oran limiti / zaman aşımı / bağlantı) logdan gelir. Maliyet, sağlayıcı bildirdiyse onun değeridir; yalnızca
  LiteLLM tahmini varsa "tahmin", hiçbiri yoksa "Strix hesaplayamadı" olarak etiketlenir. Eksik veri sıfır değil "veri yok"
  gösterilir. Araç çağrıları `agents.db`'deki araç adlarından ajan bazında sayılır.

## Şifreleme anahtarı ve veri taşımaları

Şifreleme anahtarı artık veri klasörünün **dışında** (`~/.config/skynet/secret.key`, `SKYNET_SECRET_KEY_FILE` ile
değiştirilebilir) tutulur; böylece `data/` klasörünün bir kopyası (veritabanı yedekleri, destek paketleri) tek başına
hiçbir sırrı çözemez. Daha önce `data/secret.key` konumunda üretilmiş anahtar ilk açılışta yeni konuma taşınır
(kopyalanır, doğrulanır, sonra silinir); anahtar asla yeniden üretilmez.

Şema değişiklikleri numaralı taşımalarla uygulanır (`schema_migrations` tablosu); ilk bekleyen taşımadan önce veritabanı
`data/backups/` altına yedeklenir. İlk taşıma, hedeflerde tutulan eski satır içi kimlik bilgisini bir kimlik profiline
taşır, profili hedefe ve o hedefin zamanlamalarına bağlar ve geçmiş taramalara maskeleme anlık görüntüsü ekler. Anahtar
konumu ve uygulanan taşımalar **Ayarlar** sayfasında görünür.

## Zamanlama kuralları

- Planlar SQLite'ta saklanır; uygulama her açılışta işleri yeniden kurar, planlar kaybolmaz.
- **Kaçırılan çalıştırmalar:** Uygulama kapalıyken zamanı 5 dakikadan fazla geçen çalıştırma geriye dönük başlatılmaz.
  "Kaçırıldı" olarak kaydedilir ve plan bir sonraki zamandan devam eder. Kaçırılan tek seferlik plan kapatılır.
- **Çakışma:** Aynı hedefte aktif (kuyrukta / çalışan) tarama varken yeni tarama başlatılamaz; zamanlama o çalıştırmayı "Atlandı" olarak kaydeder.
- **Hata durumunda:** Başarısız taramalar otomatik tekrarlanmaz.
- **Devam eden taramalar ve yeniden başlatma:** Strix ayrı bir süreç oturumunda çalışır. Skynet yeniden başlarsa
  hâlâ çalışan Strix süreçlerine yeniden bağlanır. Süreç ölmüşse tarama "Yarıda kaldı" olarak işaretlenir,
  artık sandbox konteyneri temizlenir ve tarama **otomatik yeniden başlatılmaz**. Kullanıcı isterse "Kaldığı yerden devam et"
  ile `strix --resume` çalıştırabilir. Kuyrukta bekleyen (hiç başlamamış) taramalar açılışta sırayla başlatılır.

## Durdurma

"Durdur" önce Strix süreç grubuna `SIGINT` gönderir; Strix raporunu yazar ve sandbox'ı kapatır. 45 saniyede kapanmazsa
`SIGTERM`, ardından `SIGKILL` gönderilir. Son olarak Strix logunda kayıtlı sandbox konteyneri hâlâ çalışıyorsa
`docker rm -f` ile kaldırılır (yalnızca o taramaya ait konteyner).

## CI / pipeline

Ayarlar > CI / pipeline erişimi bölümünden token oluşturun (yalnızca bir kez gösterilir).

```bash
SCAN=$(curl -s -X POST -H "X-API-Token: $SKYNET_TOKEN" "$SKYNET_URL/api/ci/targets/<hedef_id>/scan" | jq -r .scan_id)
while :; do
  R=$(curl -s -H "X-API-Token: $SKYNET_TOKEN" "$SKYNET_URL/api/ci/scans/$SCAN")
  [ "$(echo "$R" | jq -r .finished)" = "true" ] && break; sleep 60
done
[ "$(echo "$R" | jq -r .gate)" = "pass" ] || exit 1
```

`gate`, taramadaki "bulgu eşiği" (Strix `--fail-on`) seviyesinde veya üzerinde bulgu varsa `fail` döner.

## Strix kaynaklı sınırlamalar

- **Kapsam:** Strix'te kapsam (izinli/yasaklı host) için ayrı bir seçenek yoktur. Skynet kapsamı Strix'in belgelenmiş
  yöntemi olan talimat dosyasıyla (`--instruction-file`) iletir; kapsam teknik olarak zorlanmaz, ajanlardan uyması istenir.
- **Kimlik doğrulama:** Strix'in kendi kimlik doğrulama seçeneği yoktur. Skynet gizli değerleri talimata **yazmaz**; her
  kimlik profilini 0600 bir dosyaya yazıp `--workspace-file` ile sandbox içindeki `/workspace/skynet_auth/` altına kopyalatır
  (tarama bitince host'taki dosya silinir). Talimatta yalnızca profil adı, yöntem, gizli olmayan bilgiler (kullanıcı adı,
  başlık/çerez adları) ve dosya yolu geçer; ajanlardan dosyayı referansla kullanması istenir (`curl -H @dosya`). OAuth/token
  yenileme, MFA/TOTP ve istemci sertifikası (mTLS) sunulmaz çünkü bu primitiflerle çalışmazlar. **Strix girişin başarılı olup
  olmadığını bildirmez;** Skynet yalnızca başlık/çerez profilleri için kendi ön kontrolünü (tek HTTP isteği) ayrıca yapar.
- **İlerleme:** Strix yüzde bazlı ilerleme bildirmez. Skynet süreyi, canlı logu, ajan durumlarını ve tarama sırasında yazılan
  bulguları gösterir; yüzde veya ilerleme çubuğu uydurmaz.
- **Ön bulgular:** Tarama sürerken bulgular `vulnerabilities/*.md` dosyalarından okunur ve "ön bulgu" olarak işaretlenir.
  Nihai liste tarama sonunda `vulnerabilities.json`'dan gelir.
- **Maliyet:** Strix model fiyatını bilmediğinde `run.json` içine `0` yazar; Skynet bunu "Strix bildirmedi" olarak gösterir.
- **Kullanılan model:** `run.json` modeli içermez. Skynet modeli kendi kaydından, içe aktarılan TUI taramalarında `strix.log`'daki
  "LLM model resolved" satırından alır.
- **Sandbox konteyneri:** Strix konteynerleri taramaya özel etiketlemez. Temizlik, Strix logundaki konteyner kimliği üzerinden yapılır.

## Proje yapısı

```
skynet/
  main.py          FastAPI uygulaması: REST API, oturum, CSRF, CSP, maskeleme, statik arayüz
  runner.py        Strix süreçleri: kuyruk, başlatma, izleme, durdurma, yeniden bağlanma, içe aktarma, ingest, webhook
  scheduler.py     Zamanlamalar (APScheduler), kaçırılan çalıştırma politikası
  llm.py           LLM profilleri → Strix ortam değişkenleri, bağlantı testi, model listesi
  targets.py       Hedef → Strix hedefleri ve talimat dosyası
  campaigns.py     Kampanyalar (gruplama, arşiv, bulgu özeti)
  vault.py         Kimlik profilleri: doğrulama, --workspace-file üretimi, ön kontrol, maskeleme
  findings_store.py Bulgu parmak izi ve tekilleştirme, giderilme durumu
  inventory.py     Keşif envanteri: Strix çıktılarından host/servis/uç nokta/teknoloji çıkarımı
  telemetry.py     Tarama telemetrisi: strix.log + run.json + agents.db artımlı okuma
  redact.py        Gizli değer ve desen maskeleme
  scope.py         URL/host normalizasyonu ve kapsam etiketleme
  runs.py          strix_runs/<run> klasörünü okuma (run.json, bulgular, ajanlar, log)
  auth.py          Giriş, oturum çerezi, CI token
  crypto.py        Gizli değerlerin şifrelenmesi (anahtar veri klasörü dışında; vault alt anahtarı)
  db.py            SQLite şeması ve numaralı taşımalar
  static/          Bağımlılıksız arayüz (harici CDN yok; kurum içi ağda çalışır)
tests/             Birim testleri (kapsam, parmak izi, maskeleme, telemetri, taşıma)
```

Testler: `python -m unittest discover -s tests` (geçici bir veri klasörü kullanır; gerçek `data/` klasörüne dokunmaz).

Yalnızca yetkili olduğunuz sistemleri tarayın.
