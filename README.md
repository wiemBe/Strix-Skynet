# Skynet

Skynet, uygulamaları production'a çıkmadan önce ve sonrasında düzenli aralıklarla pentestten geçirmek için
kullanılan web tabanlı yönetim arayüzüdür. Pentest motoru olarak makinede kurulu **[Strix](https://github.com/usestrix/strix)**
CLI'ını kullanır; Strix'i yeniden yazmaz, yalnızca taramaları başlatır, izler, zamanlar ve sonuçlarını gösterir.

- Hedef yönetimi: uygulama, adres, ortam (development / test / staging / production), kapsam içi/dışı, kimlik doğrulama
- Anlık tarama, kuyruk, canlı log ve ajan durumu, güvenli durdurma (alt süreçler ve sandbox konteyneri dahil)
- Zamanlama: tek seferlik, günlük, haftalık, saat aralıklı ve cron; duraklat / etkinleştir / düzenle / sil
- Tarama geçmişi, Strix'in ürettiği gerçek bulgular ve raporlar, SARIF/CSV/JSON/Markdown indirme
- LLM bağlantı profilleri: OpenRouter ve kurum içi LiteLLM, kod değişikliği olmadan geçiş
- Prod öncesi CI kullanımı için token korumalı API (bulgu eşiği: pass/fail)

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
| `SKYNET_SECRET_KEY` | (`data/secret.key` üretilir) | Gizli değerlerin şifreleme anahtarı (Fernet) |
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

- **Kapsam ve kimlik doğrulama:** Strix'te kapsam (izinli/yasaklı host) veya kimlik bilgisi için ayrı bir seçenek yoktur.
  Skynet bu bilgileri Strix'in belgelenmiş yöntemi olan talimat dosyasıyla (`--instruction-file`) iletir. Kapsam teknik olarak
  zorlanmaz, ajanlardan uyması istenir. Talimat (kimlik bilgileri dahil) seçilen LLM sağlayıcısına gönderilir.
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
  main.py       FastAPI uygulaması: REST API, oturum, CSRF, CSP, statik arayüz
  runner.py     Strix süreçleri: kuyruk, başlatma, izleme, durdurma, yeniden bağlanma, içe aktarma, webhook
  scheduler.py  Zamanlamalar (APScheduler), kaçırılan çalıştırma politikası
  llm.py        LLM profilleri → Strix ortam değişkenleri, bağlantı testi, model listesi
  targets.py    Hedef → Strix hedefleri ve talimat dosyası
  runs.py       strix_runs/<run> klasörünü okuma (run.json, bulgular, ajanlar, log)
  auth.py       Giriş, oturum çerezi, CI token
  crypto.py     Gizli değerlerin şifrelenmesi
  db.py         SQLite şeması
  static/       Bağımlılıksız arayüz (harici CDN yok; kurum içi ağda çalışır)
```

Yalnızca yetkili olduğunuz sistemleri tarayın.
