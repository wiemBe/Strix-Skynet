# Skynet

Güncel çalışma ve doğrulama takibi: [PROGRESS.md](PROGRESS.md). Arayüz dili İngilizce, varsayılan saat dilimi Europe/Istanbul.

Skynet, uygulamaları production'a çıkmadan önce ve sonrasında düzenli aralıklarla pentestten geçirmek için
kullanılan web tabanlı yönetim arayüzüdür. Pentest motoru olarak makinede kurulu **[Strix](https://github.com/usestrix/strix)**
CLI'ını kullanır; Strix'i yeniden yazmaz, yalnızca taramaları başlatır, izler, zamanlar ve sonuçlarını gösterir.

- Hedef yönetimi: uygulama, adres, ortam (development / test / staging / production), kapsam içi/dışı
- **Kampanyalar:** birden çok hedefi, taramayı ve zamanlamayı tek angajman altında toplama; bulgu aday grupları özeti
- **Kimlik profilleri (vault):** yeniden kullanılabilir kimlik doğrulama (anonim / kullanıcı+şifre / başlık / çerez); sırlar şifreli saklanır ve taramaya yalnızca sandbox dosyası olarak verilir, talimata yazılmaz
- **Keşif envanteri:** taramalarda bulunan host, servis, uç nokta ve teknolojiler; kanıt düzeyi (gözlemlendi / ajan bildirdi), kapsam etiketi ve tarama arası değişim
- **Tarama telemetrisi:** model çağrısı, yeniden deneme (oran limiti/zaman aşımı/bağlantı), gecikme, maliyet kaynağı, token ve ajan başına araç kullanımı
- Anlık tarama, kuyruk, canlı log ve ajan durumu, güvenli durdurma (alt süreçler ve sandbox konteyneri dahil)
- Zamanlama: tek seferlik, günlük, haftalık, saat aralıklı ve cron; duraklat / etkinleştir / düzenle / sil
- Tarama geçmişi, bulgu aday grupları (giderilme durumu), Strix raporları, SARIF/CSV/JSON/Markdown indirme
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
Settings > Admin password bölümünden değiştirilebilir.

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

**Kurum içine geçiş:** Settings > LLM connections > Add connection → Sağlayıcı "LiteLLM", base URL
`http://litellm.kurum.local:4000`, LiteLLM virtual key ve gateway'deki model adı → **Test connection**
(model listesi gelir) → **Make default**. Kod değişikliği gerekmez; OpenRouter profili kullanılabilir kalır.

Güvenlik kuralları:
- API anahtarları veritabanında şifreli saklanır, tarayıcıya hiçbir zaman gönderilmez, loglara yazılmaz.
- Her tarama ve zamanlama, kaydedildiği bağlantı profilini kullanır. Profil hata verirse **başka profile otomatik geçilmez**.
- Skynet'in kendi ortamındaki `OPENAI_API_KEY`, `LLM_API_BASE` gibi değişkenler Strix sürecine aktarılmaz; böylece veriler
  yanlışlıkla başka bir sağlayıcıya gitmez.
- Strix telemetrisi (`STRIX_TELEMETRY`) varsayılan olarak **kapalı** başlatılır (Strix'in kendi varsayılanı açıktır).

## Kampanyalar, kimlik profilleri, envanter ve telemetri

- **Kampanyalar** yalnızca gruplamadır: hedefleri, taramaları ve zamanlamaları bir angajman altında toplar ve
  bulgu aday grupları özetini gösterir. Taramanın nasıl çalıştığını değiştirmez. Kampanya silme yalnızca arşivlenmiş
  kampanyada mümkündür ve sadece bağlantıları koparır; taramalar, bulgular ve zamanlamalar korunur.
- **Kimlik profilleri** hedeflere atanır; bir tarama yalnızca atandığı profilleri kullanabilir. Profil silinir veya bir
  hedeften kaldırılırsa onu kullanan zamanlamalar otomatik duraklatılır ve bir olay kaydı yazılır (sessizce kimlik
  doğrulamasız çalışmaz). Sırlar türetilmiş bir anahtarla ayrıca şifrelenir; her taramaya başlarken kullanılan değerler
  şifreli bir anlık görüntü olarak saklanır, böylece profil sonradan değişse bile eski taramalardaki maskeleme bozulmaz.
- **Bulgular** host + yöntem + normalize uç nokta + CWE parmak iziyle aday gruplara ayrılır. Bu eşleşme tek başına aynı açık olduğunun kanıtı değildir. Her görülme kendi taramasına bağlı
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

Settings > CI / pipeline access bölümünden token oluşturun (yalnızca bir kez gösterilir).

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
  activity.py      Live activity: agents.db'den artımlı, maskeli ajan mesajı / araç akışı
  verify.py        Bulgu doğrulama çalışmaları ve muhafazakâr kanıt sınıflandırması
  control.py       Canlı ajana mesaj: başlatıcı seçimi, yerel kontrol ucu, şifreli denetim kaydı, durumlar
  strix_bridge.py  Strix runtime'ında çalışan ince başlatıcı (resmi CLI + mesaj kanalı; yalnızca stdlib import)
  auth.py          Giriş, oturum çerezi, CI token
  crypto.py        Gizli değerlerin şifrelenmesi (anahtar veri klasörü dışında; vault alt anahtarı)
  db.py            SQLite şeması ve numaralı taşımalar
  static/          Bağımlılıksız arayüz (harici CDN yok; kurum içi ağda çalışır)
tests/             Birim ve API testleri; tests/runtime/ Strix runtime'ında çalışan gerçek koordinatör kontrolleri
```

Testler: `python -m unittest discover -s tests` (geçici bir veri klasörü kullanır; gerçek `data/` klasörüne dokunmaz).

Yalnızca yetkili olduğunuz sistemleri tarayın.


## Live activity ve bulgu doğrulama

**Live activity** tarama detayında görünür ajan mesajlarını ve araç çağrısı/yanıtlarını mevcut
`.state/agents.db` verisinden iki saniyede bir artımlı okur. Gerçek ajan hiyerarşisi sağdadır;
ajan seçimi akışı filtreler. Araç çağrısı ve yanıtı tek açılır kartta birleşir. Auto-follow kapatıldığında
okuma konumu korunur. Bağlantı kesilirse son kayıtlar görünmeye devam eder. Tamamlanmış taramalarda
bu alan açıkça **Recorded session** olarak etiketlenir. Reasoning öğeleri, kullanıcı promptları,
sağlayıcı metadatası ve ikili içerikler akışa alınmaz. Görünür metinler gönderilmeden önce maskelenir.

Bulgu detayındaki **Verify / Re-verify**, mevcut runner/kuyruk/iptal mekanizmasıyla ayrı ve odaklı bir
Strix çalışması oluşturur. LLM bağlantısı, güncel atanmış Vault profilleri, bütçe ve tur sınırı seçilebilir.
`finding_verifications`, bulgu grubu ve taramayla bağlantıyı; sır içermeyen profil sürüm/karşılaştırma
metadatasını; zamanları, sonucu ve kanıt referanslarını saklar. Kuyrukta profil yenilenirse başlangıçta
güncel sürüm okunur. Eski tarama sırları yalnızca maskelemede kullanılır, kimlik doğrulamada kullanılmaz.

- `reverified`: Bu çalıştırmaya ait saldırı/kontrol istekleri ve tam yanıtları, ilişkili Strix değerlendirmesi,
  yeni bulgu, yeni PoC/kanıt ve bulgunun `http_exchange_ids` bağlantısı birlikte doğrulanır.
- `not_reproduced`: İlgili testin tamamlandığı ve gereken oturum/erişimin test istekleri boyunca doğrulandığı
  gösterilir. Başlık/çerez profillerinde güncel kimlik materyali eşleşmesi ve korumalı kimlik belirteci aranır.
- `inconclusive`: Kanıt, tamamlanmış test, erişim veya oturum doğrulanamaz. Form-login sürekliliği mevcut
  kayıtlarla kanıtlanamıyorsa bu sonuç kullanılır. İptal/kesinti de negatif sonuç değildir.
- `error`: Çalışma teknik hatayla sonlanır.

Parmak izi eşleşmesi, tek endpoint isteği, HTTP 200/redirect, temiz çıkış veya başarılı Skynet ön kontrolü
tek başına yeterli değildir. Strix kanıt sözleşmesini tamamlamazsa değerlendirme `inconclusive` kalır.
Orijinal bulgu dosyaları ve observation kayıtları korunur; hiçbir sonuç giderilme durumunu otomatik değiştirmez.
Eski sınıflandırmalar önceki sonuç ve gerekçe korunarak yeniden değerlendirilebilir; tarama yeniden başlatılmaz.

Migration 2 doğrulama tablosunu, migration 3 ayrı kanıt alanını ve sınıflandırma sürümünü ekler. Her bekleyen
migration grubu öncesi SQLite backup API kullanılır; WAL verisi tutarlı yedeğe dahildir. Anahtar bulunamıyor
ama şifreli kayıtlar varsa yeni anahtar üretilmez. Anahtar konumu, şema sürümü ve migration yedek yolları
**Settings > Data protection** altında görünür.

## Canlı ajana mesaj

Çalışan bir taramada **Live activity** altındaki composer ile running/waiting durumdaki herhangi bir ajana
talimat gönderilebilir. Ağaçtan ajan seçmek composer hedefini de değiştirir; yazılan taslak 2 sn'lik
yenilemelerde silinmez.

**Nasıl çalışır.** Strix headless (`--non-interactive`) modda kullanıcı mesajı kabul etmez: native
`AgentCoordinator.send(from="user")` çalışan ajanı kesmeden `waiting` yapar, bütçe duraklatmasını açabilir ve
gelen kutusu yalnızca `wait_for_agents` ile okunur. Bu yüzden Skynet taramayı ayrı Strix runtime'ı
(`.strix-runtime/`, `strix-agent==1.7.0`) üzerinde `skynet/strix_bridge.py` ile başlatır. Köprü resmi Strix CLI
giriş noktasını aynen çalıştırır ve sürüme sabitlenmiş iki genel parametreye bağlanır:
`run_strix_scan(coordinator=...)` (ajan durumunu yalnızca okur) ve openai-agents
`RunConfig.call_model_input_filter`. Ajanın bir sonraki model çağrısından önce o ajana sıralanmış mesajlar
Strix oturumuna (agents.db) doğru sırada eklenir ve o çağrının girdisine konur. Ajan durumu, native mailbox
ve ajanlar arası mesajlaşma değiştirilmez. Mesaj başlığı, sistem promptundaki kapsam kurallarının geçerli
olduğunu ajana hatırlatır.

**Durumlar** yalnızca gözlenebileni söyler: `Sending`, `Queued for next model call` (Strix kabul etti),
`In agent context` (ajanın oturumuna ve model çağrısına eklendi), `Not delivered` (ajan veya tarama önce
bitti), `Rejected` (ajan aktif değil, bütçe duraklatması, kapanış, kuyruk dolu), `Unconfirmed` (zaman aşımı;
kabul edilmiş olabilir, otomatik yeniden gönderilmez). Ajanın talimatı uygulayıp uygulamadığı iddia edilmez;
bu activity akışında görülür. Bütçe sınırında duraklatılmış tarama mesajla sürdürülmez, bütçe değiştirilmez.

**Güvenlik.** Kontrol ucu yalnızca `127.0.0.1`, geçici port ve rastgele bearer token kullanır; Host başlığı
denetlenir. Port/token 0600 manifest dosyasındadır (`data/runtime/scan_<id>_control.json`); Skynet PID, protokol,
izinler ve sahipliği doğrular, yalnızca sabit host'a bağlanır ve yönlendirme izlemez. Süreç bitince manifest
silinir; durum dosyası içerik taşımaz. Skynet API'si oturum + CSRF ister. Mesajlar Vault anahtarıyla şifreli
`agent_messages` tablosunda saklanır, arayüzde taramanın maskeleme kurallarıyla gösterilir. `request_id`
ile idempotent: aynı ID tekrar gönderilirse köprü yinelemeyi reddeder, farklı içerik `409` döner.
Sırları mesaj yerine Vault profillerinde tutun.

**Uygunluk.** Köprü yalnızca runtime sürümü yapılandırılmış Strix binary sürümüyle aynıysa kullanılır
(motor sessizce başka sürüme geçmez). Değilse veya Settings'te kapalıysa tarama eskisi gibi binary ile başlar ve
composer gerekçeyi gösterir. Köprü eklenemezse (desteklenmeyen sürüm) Strix yine çalışır, mesajlaşma
kullanılamaz görünür. Runtime kurulumu: Python 3.12 ile `.strix-runtime` venv'i ve
`pip install strix-agent==<binary sürümü>`. Migration 4 `agent_messages` tablosunu ve
`scans.control_mode/control_note` alanlarını ekler (öncesinde yedek alınır).

Bu geliştirme oturumunun test kapsamı ve canlı motor çalıştırması sınırları [PROGRESS.md](PROGRESS.md)'dedir.
