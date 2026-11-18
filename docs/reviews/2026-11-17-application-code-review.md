# Skynet uygulama kodu incelemesi — 17 Kasım 2026

İlk turdaki rapor geliştirmesinden sonra inceleme uygulamanın diğer veri ve yürütme yollarına genişletildi.
Amaç yalnızca biçim veya kod uzunluğu değildi: kullanıcıya gösterilen sonucun, kullanılan kanıtın ve başlatılan
taramanın gerçekten aynı şeyi ifade edip etmediği kontrol edildi. Doğrulanmış sorunlar aşağıda ayrı ayrı kayıtlı.

## Kapsam ve yöntem

`skynet/`, `scripts/` ve `deploy/` altındaki uygulama kaynaklarının envanteri **48 dosya / 13.919 satır**.
[Dosya, satır sayısı ve SHA-256 listesi](../qa/2026-11-17-code-review/source-inventory.json) son kaynak durumunu
tanımlar. Bu sayı, bütün satırlar için kusursuzluk veya tüm olası davranışların test edildiği iddiası değildir.

| Alan | İncelenen başlıca yollar |
|---|---|
| Kimlik / yetki / audit | `auth.py`, `audit.py`, `main.py` security middleware, kullanıcı ve CI rotaları; rol tablosu, kalıcı oturum iptali, mutation audit |
| Vault / şifreleme | `vault.py`, `crypto.py`, `redact.py`, LLM anahtarı kullanımı; güncel değerler, tarihsel snapshot, bozuk kayıt ve resume |
| Tarama yaşam döngüsü | `runner.py`, `scheduler.py`, `targets.py`, `control.py`, `strix_bridge.py`; enqueue, launch, kayıt/monitor, iptal, finalization, recovery, import |
| Veri / rapor | `db.py`, `runs.py`, `findings_store.py`, `campaigns.py`, `report.py`; seçimin kapsamı, eksik çıktı, tarih, CI kapısı, JSON/Markdown |
| Kanıt / değerlendirme | `evidence.py`, `verify.py`, `coverage_matrix.py`, `session_health.py`, `workspace.py`, `compare.py`; kaynak bağlantıları, rol/origin, kesme ve maskeleme |
| İzleme | `activity.py`, `timeline.py`, `browser.py`, `telemetry.py`, `inventory.py`, `siem.py`; salt okuma, sıralama, sırlar, görüntü politikası, syslog outbox |
| Arayüz | `app.js`, `sky.js`, login/static dosyaları; HTML metin sınırı, sekme/sayfa yarışları, yetki düğmeleri, rapor ve kanıt etiketleri |
| Kurulum | runtime kurucusu, doctor, run relocation, RHEL/Nginx kurucuları ve systemd birimi; allowlist, backup, dry-run ve kapsam sınırları |

Mevcut testler çalıştırıldı; eksik sınır durumları ayrı regresyonlarla eklendi. İlk yeni test çalıştırması mevcut
kodda **10 başarısızlık ve 1 hata** üretti. Yeni kanıt-kesme testi daha sonra gerçek `agents.db` fikstürüyle
güçlendirildi. Testlerdeki sırlar rastgele QA değerleridir; gerçek kimlik bilgileri kullanılmadı.

## Düzeltilen sorunlar

| Kimlik / önem | Önceki davranış | Düzeltme ve doğrulama |
|---|---|---|
| CR-01 / P1 | Log API'sine sır değerinin ortasındaki byte offset verilince sır son eki görünüyordu. 256 KB sınırında tek uzun satır da sır ön eki yayımlayabiliyordu. | `runs.tail_lines` yalnız tam satırları yayımlar; parçalı ilk satırı/uzun satırları atlar, kısa bitmemiş satırı sonraki polla bırakır. Offset ortası, uzun satır, sonraki satıra ilerleme ve yarım satır test edildi. Ham `tail` yalnız iç okuyucular için korundu. |
| CR-02 / P1 | HTTP kanıtı 64.000 karakterde kesildikten sonra maskeleniyordu. Kapsamda unmapped surface ve bazı gerekçeler de maskelenmeden kısaltılıyordu. | Kanıt ham iç kaynakta korunur, önce maskelenir sonra public preview kesilir. Kapsamın gösterilecek metni kısaltmadan önce maskelenir. Gerçek mesaj deposunda sınırı kesen sır ve unmapped surface testi var. |
| CR-03 / P1 | Resume sonrası occurrence yeni scan'e taşınınca aynı Strix run'ındaki eski snapshot maskeleri kaybolabiliyordu. | Scan/bulgu redactor'ı aynı run'ın tarihsel snapshot'larını da kullanır. Yeni launch snapshot'ı eski ve güncel değerleri birleştirir; zaman çizelgesi maskeleme revizyonu da bu değişimi kapsar. Eski/yeni sır birlikte test edildi. |
| CR-04 / P1 | Çözülemeyen snapshot/profil bazı okuma yollarında boş maskeleme listesine dönüşüyordu. | Çözülemeyen/yanlış biçimli bağlam artık sessizce atlanmaz; `DecryptError` ve API 503 olur. Tam yeni değerlerle bozuk profil onarılabilir; boş/eksik replacement eski şifreli değeri silemez. |
| CR-05 / P1 | Envanter, asset observation ve telemetri yanıtlarında saklanan metadata yeniden maskelenmiyordu; mesajlarda yalnız content maskeleniyordu. | Okuma anında tarihsel/güncel maskeler uygulanır. Ajan adı, açıklama ve yazar dahil mesaj çıktısı birlikte maskelenir. Üç gerçek API ve mesaj sunum testi var. |
| CR-06 / P1 | `https://example.test` kapsamı varsayılan 443 yerine aynı host'un başka portlarını da içeriyordu. Port bilinmeyince de kapsam içi denebiliyordu. | URL'nin etkin portu korunur. 443 içeri, 8080 dışarı, bilinmeyen port unknown. Çıplak hostname kuralının mevcut porttan bağımsız anlamı korunur. |
| CR-07 / P1 | Eksik/bozuk son bulgu dosyası sıfır bulgu ve CI pass üretebiliyordu. Geçmiş completed scan altında iptal edilmiş run'ın pass sonucu da yayımlanabiliyordu. | Pass için geçerli son liste ve completed run gerekir. Bilinen yüksek bulgu fail kalabilir; eksik veri pass olmaz. CI ve yönetici özeti eksik sonuçları açıklar. Bozuk JSON, yanlış şekil, karışık liste, geçerli boş liste ve incomplete run test edildi. |
| CR-08 / P1 | `Popen` başarılı, ardından DB/verification kaydı veya monitor başlatma başarısız olursa süreç kontrolsüz devam edebilirdi. | Maskeleme snapshot'ı process output'tan önce kalıcılaşır. Spawn sonrası registration/monitor handoff hatasında süreç grubu TERM→gerekirse KILL ile sonlandırılır ve beklenir. Gerçek süreç başlatmadan DB hatası enjekte eden test var. |
| CR-09 / P2 | Kampanya detayında tüm sistemin son 200 scan'i alınıp kampanya filtresi sonra uygulanıyordu. Eski kampanya boş görünebiliyordu. Hedef bulgu listesi 5.000 scan'de kesiliyordu. | Kampanya filtresi SQL'de limitten önce uygulanır. Hedef bulguları bütün saklanan scan kimliklerini kullanır. Başka 210 yeni scan arasındaki eski kampanya ve raporun 5.000+ geçmiş testi geçiyor. |
| CR-10 / P2 | Endpoint normalizasyonu 300 karakterden sonrasını atıp farklı uzun yolları aynı kimliğe dönüştürüyordu. | Kimlik üretirken yol kesilmiyor; aynı uzun öneke sahip farklı endpoint'ler farklı kalıyor. |
| CR-11 / P2 | Bozuk LLM anahtarı boş anahtar gibi işlenebiliyor, bozuk CI token'ı istek sırasında yenilenebiliyordu. | İki yol da strict decrypt kullanır; key'siz LiteLLM yalnız gerçekten key kaydı yoksa kullanılır. Bozuk CI değeri değiştirilmez ve 503 döner. |
| CR-12 / P2 | ASCII dışı imza içeren bozuk session cookie'si `compare_digest` TypeError/500 üretiyordu. | İmza byte dizileriyle karşılaştırılır; hatalı cookie normal 401 olur. |
| CR-13 / P2 | Interval preview'de geçersiz saat dilimi validation'dan önce `_anchor_interval` içinde exception üretiyordu. | Saat dilimi validation sonucuna dönüyor; preview `ok:false`, form normal hata mesajı alır. |
| CR-14 / P2 | Yavaş eski sayfa/sekme yanıtı sonradan dönüp yeni seçimin içeriğini ezebiliyordu. | GET yanıtları başladıkları hash ile eşleştirilir; scan sekmesi render generation ile korunur. Kontrollü ters yanıt sırasıyla iki Node testi gerçek JS kodunu çalıştırır. Mutasyon istekleri iptal edilmez. |
| CR-15 / P2 | Kaynak complete olsa bile gösterimi clipped olan kanıt “Complete” etiketleniyor, diff/download tamamlanmış gibi görünebiliyordu. | UI “Preview clipped” gösterir; diff'in complete alanı clipping/4.000 satır sınırını dikkate alır; metin indirmesinde kesilme etiketi vardır. |
| CR-16 / P2 | Talimat sonrası activity API'sine eski/negatif cursor verilince talimat öncesi aktivite dönebiliyordu. | Cursor, talimat işaretinin bulunduğu konumun altına inemez. `after=-1` için gerçek rota testi var. |
| CR-17 / P3 | Bazı Stop/Delete/Recheck/Import etiketleri frontend rol eşlemesinde yoktu. Accepted/false-positive dahil tüm kapalı gruplar “all resolved” olarak sunulabiliyordu. | İlgili eylemler rol eşlemesine eklendi; bulgu özeti “None open / currently marked open” der. Backend'in mevcut yetki kontrolleri korundu. Kalan Türkçe sistem durumu İngilizceleştirildi. |

İlk turdaki rapor geliştirmesi de korunuyor: özet/ayrıntılı seçim, tüm durumlarıyla bulgu listesi, güncel kapsam,
analist notları, kaynak scan'ler, deterministik yönetici özeti ve Markdown dışa aktarma. Tarih sıralaması gerçek
datetime değerleriyle yapılır; gelecekte/ters tarihler sıfıra çevrilmez.

## Doğrulama sonucu

- **246 Python testi geçti**; bu incelemede 22, önceki rapor turunda 10 yeni regresyon bulunuyor.
- **2 Node arayüz testi geçti** (`node tests/test_frontend.cjs`).
- Python compileall, üç JS dosyasının sözdizimi ve `git diff --check` geçti.
- Testlerin localhost bridge/SIEM soketleri için sandbox dışında çalıştırılması gerekti; dış hedef taraması
  yapılmadı. Mevcut SQLite ResourceWarning mesajları testleri başarısız kılmadı.
- Gerçek uygulama UI'si, geçici DB ve sentetik 12 bulgulu hedef/kampanya ile 1366×768 / 1920×1080'de kontrol
  edildi. Ayrıntılı listede 12 bulgu; kampanya scan tablosunda ilgili kayıt; son seçilen Details sekmesinde doğru
  içerik; yatay taşma ve browser warning/error yok. Viewer scan başlatma düğmesini görmedi, rapor okuyup
  Markdown indirebildi. [QA ekranları](../qa/2026-11-17-code-review/README.md).

## Sınırlar ve kalan tasarım konuları

Bu bir kaynak incelemesi ve regresyon çalışmasıdır; tam güvenlik denetimi/sertifikasyon veya bütün olası
girdiler için hatasızlık garantisi değildir. Paketlenmiş üçüncü taraf Strix ve Python bağımlılıklarının bütün
kaynakları yeniden denetlenmedi. Mevcut native bridge testleri çalıştı; yeni Strix/LLM pentesti başlatılmadı.

- **Bulgu fingerprint'i hâlâ aday korelasyondur.** Mevcut veri modeli host+yöntem+normalize yol+CWE kullanır;
  scheme/port ayrı group alanları değildir. Aynı host üzerinde farklı portlarda aynı yol/CWE varsa tek aday
  grupta toplanabilir. Bu köklü model değişikliği mevcut grup kimliklerini, manuel durumları ve kanıt ilişkilerini
  taşıyan ayrı bir migration gerektirir; bu incelemede geçmiş kayıtlar otomatik yeniden gruplanmadı.
- **PDF sayfa sayfa kabulü yapılmadı.** Önceki turda gömülü browser'ın print otomasyonu zaman aşımına uğramıştı.
  Ekran/Markdown doğrulaması gerçek PDF dosyasının doğrulanması yerine geçmez.
- Audit/syslog verileri için otomatik saklama/silme politikası hâlâ yok; geçmiş kayıtlar kendiliğinden silinmez.
- Kaynak dosyalar ve test verileri düzeltildi; gerçek `data/`, mevcut anahtarlar, geçmiş yedekler ve Strix çıktı
  dosyaları yeniden yazılmadı. Okuma sırasında yeni maskeleme uygulanması, eski dosyaları/backup'ları temizlemez.
- Gerçek RHEL host'ta systemd/SELinux/firewalld/Docker sandbox kabulü bu çalışmanın kapsamına alınmadı.

Commit, push, deploy veya asıl servisin yeniden başlatılması yapılmadı.
