# Skynet — çalışma takibi

Güncelleme: 15 Kasım 2026 · Europe/Istanbul (son bölüm: canlı ajana mesaj)

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
