# SKY-01…07 bağımsız kod incelemesi

> **Güncel durum:** Buradaki R1–R6 bulguları düzeltildi. Son kod/test/QA kanıtları
> [2026-11-15-sky-fixes.md](2026-11-15-sky-fixes.md) dosyasında. Aşağıdaki sonuçlar ve satır numaraları ilk incelemeye aittir.

15 Kasım 2026 · temel HEAD `b4a0695` ve çalışma ağacındaki Claude değişiklikleri.

**Sonuç: 124 test geçiyor; üç yüksek öncelikli, üç orta öncelikli tekrarlanabilir kusur var.
“Yedi özellik kabul ölçütleriyle tamamlandı” sonucunu desteklemiyorum.**

Bu inceleme uygulama kodunu düzeltmedi. Rapor, izole tekrar üretim betiği ve görsel QA kayıtları eklendi.
Önceki çalışma ağacı korundu. Commit/deploy yapılmadı; asıl `data/` ve anahtar değiştirilmedi.

## Doğrulama

- `.venv/bin/python -m unittest discover -s tests` → 124 test, OK.
  İlk sandbox çalışması yerel soket izni nedeniyle 13 error / 2 failure verdi;
  izinli tekrar çalışmada hepsi geçti. Bunlar ürün hatası olarak sayılmadı.
- Python compileall, `node --check` (app.js ve sky.js), `git diff --check` geçti.
- Ek kusurlar mevcut testlerin kapsamadığı izole fixture senaryolarıyla tekrar üretildi:
  `.venv/bin/python docs/reviews/reproduce_sky_issues.py`.
- Betik tüm DB/anahtar/çalışma kayıtlarını geçici dizinlere yazar; ağ, sağlayıcı veya Strix taraması başlatmaz.
  Çıktı: [reproductions.json](../qa/2026-11-15-review/reproductions.json).
- UI: önceki yerel QA geçmişinin SQLite backup API ile ayrı kopyası, yalnız read-history lifespan,
  127.0.0.1:8793; queue/scheduler/import/backfill/recovery kapalı. Yeni pentest/LLM çağrısı yapılmadı.
- Yedi görünüm 1366×768 ve 1920×1080'de kontrol edildi; sayfa genelinde yatay taşma ve konsol hatası yok.
  Kanıt: [görseller ve ölçümler](../qa/2026-11-15-review).

## R1 — P1: Vault değişince zaman çizelgesi eski, maskelenmemiş çıktıyı döndürüyor

Konum: `skynet/timeline.py:180–194`, özellikle cache hit'in redactor oluşturulmadan dönmesi.

Tetikleyici: Zaman çizelgesindeki serbest metinde bir değer var; sonra aynı değer Vault'a sır olarak ekleniyor
veya profil o değere rotasyon yapıyor. Çalışma dosyaları değişmiyor.
`_sig` yalnız dosya zamanları/scan/mesaj durumlarına bakıyor; Vault sır kümesini hesaba katmıyor.

Tekrar üretim: Yeni Vault kaydından sonra güncel `vault.scan_redactor` değeri maskeliyor,
ama ikinci `timeline.page` cevabı cache'ten aynı sentetik sırrı açık döndürüyor.
Tamamlanmış taramalarda dosya değişmediği için bu durum süreç/cache yenilenene kadar devam edebilir.

Etki: Kullanıcıya sunulan API/log benzeri görünümde güncel maskeleme kuralı uygulanmıyor.
Gerçek bir kullanıcı sırrı sızdırılmadı; tespit yalnız fixture değeriyle yapıldı.

Beklenen düzeltme: Cache'in maskeleme bağlamını kapsaması veya gönderim öncesi güncel maskeleme;
istemcide aynı kimlikli olayın eski metninin korunması da dikkate alınmalı.
Regresyon: Cache doluyken profil ekleme/rotasyon sonrası hem API hem görünüm yeni kurala uymalı.

## R2 — P1: Farklı hostların kanıtları aynı kapsam hücresinde birleşiyor

Konum: `skynet/coverage_matrix.py:71–78` ve `113–127`; `compare._cell_index` de host içermeyen hücreleri kullanıyor.

Tam URL'li coverage yüzeyi hostu atılıp yalnız `(method, normalized path)` oluyor.
Trafikte `evidence.location` host/port döndürüyor ama ikisi de gruplanırken atılıyor.

Tekrar üretim: Coverage iddiası `GET http://127.0.0.1:8899/api/orders/{id}`;
iki tam kanıtın gerçek Host'u `other.internal:8899`. Sonuç yine hedef için `Tested`.
Betik yalnız kayıtları değiştiriyor; diğer hosta trafik gönderilmiyor.

Etki: Aynı path'e sahip farklı uygulama/port kanıtları birbirini tamamlayabilir;
karşılaştırma yanlış hedefe test kapsamı atfedebilir.

Beklenen düzeltme: Kimlikte normalleştirilmiş origin/host/port + method + path korunmalı;
host içermeyen claim'ler birden çok origin'e uyuyorsa belirsizlik açık kalmalı.
Regresyon: İki host ve iki port için aynı path ayrı hücreler/kanıtlar olarak kalmalı.

## R3 — P1: İki sıradan istek, ilgisiz bir güvenlik testini “Tested” yapıyor

Konum: `skynet/coverage_matrix.py:238–271`, özellikle `len(distinct) >= 2` kararı;
`_linked` aynı ajanın önceki endpoint trafiğini test bağlantısı kabul ediyor.

Tekrar üretim: Aynı profilin `/api/orders/1` ve `/api/orders/2` için iki normal başarılı GET kaydı;
SQL injection payload'ı, ilgili kontrol veya test yürütme kaydı yok. Coverage metnine “SQL injection tested”
yazılınca sonuç `WSTG-INPV / Tested / 2 evidence` oluyor.

Etki: Test kategorisinin yürütüldüğü kanıtlanmadan kanıtlı test kapsamı iddiası üretiliyor.
Bu, “ajanın test ettim demesi yeterli değil” kabul ölçütünü karşılamıyor.

Beklenen düzeltme: Bir test iddiasını doğrulayacak test türüne bağlı yürütme/kanıt bağlantısı;
bu bağlantı yoksa ordinary traffic + claim en fazla kısmi/bilinmiyor kalmalı.
Sadece istek sayısını artırmak çözüm değildir. Her test türü için zorunlu bir exploit biçimi uydurulmamalı.

## R4 — P2: Replay yeni coverage sonucunu geçmişte olmuş gibi gösteriyor

Konum: `skynet/timeline.py:157–166`.

Coverage kaydının bugünkü outcome'u hem `recorded_at` hem `updated_at` olayının özeti olarak kullanılıyor.
Tekrar üretim: Kayıt 09:00'da açılmış, son durum `reported` ve güncelleme 10:00.
Zaman çizelgesinde 09:00 olayının özeti de `reported`; 09:30'a replay yapıldığında henüz bilinmeyen sonuç görülüyor.

Beklenen düzeltme: Gerçek revizyon/olay kaynağı varsa onu kullan; yoksa başlangıç olayına yalnız kayıt oluşturulmasını
yaz, eski outcome'u uydurma. Güncel durum, geçmişte bilinen durumdan ayrı gösterilmeli.

## R5 — P2: Eşzamanlı çelişkili oturum sinyallerinde request ID durum belirliyor

Konum: `skynet/session_health.py:115–116` (sıralama), `138–152` (son belirleyici sinyal).

Aynı kaynak zamanına sahip verified ve lost kanıtları `request_id` ile sıralanıp sonuncusu kesin durum oluyor.
Belirsizlik koruması yalnız viewed/None zaman kaynaklarına bakıyor; aynı Caido/Date zamanını ele almıyor.

Tekrar üretim: Aynı 09:00:01 zamanındaki iki kayıtta ID 1 verified / ID 2 lost → lost;
ID 1 lost / ID 2 verified → verified. Kaynak zamanına göre sıraları kanıtlanmış değil.

Beklenen düzeltme: Zaman çözünürlüğü nedeniyle sıralanamayan son çelişkili sinyaller `Unknown` kalmalı;
gerçek ve yeterince hassas kaynak sırası varsa ancak o kullanılmalı.

## R6 — P2: Canlı akışta 500'den büyük yeni olay partisi eksik okunuyor

Konum: `skynet/timeline.py:213–224` ve `skynet/static/sky.js:314–321`.

Backend `now` imlecini bütün olayların maksimum first-seen zamanına taşıyor ama en fazla 500 olay döndürüyor.
İstemci sayfanın kalanını tüketmeden `seenAt = d.now` yapıyor.

Tekrar üretim: Bir poll arasında 600 olay ekle. Cevap `matched=600`, dönen 500;
cevabın `now` değeriyle sonraki poll 0 olay döndürüyor. Son 100 olay canlı takipten atlanıyor.
Özellikle eski zamanlı geç gelen olaylarda genel offset ile “Load more” da bu eksikleri güvenilir tamamlamaz.

Beklenen düzeltme: Sabit batch/snapshot üzerinden bütün sayfaları tüketmeden high-water mark'ı ilerletme
veya tekil olay kimliğini içeren kayıpsız bir continuation cursor kullan.
Regresyon: 500+ yeni ve eski zamanlı geç olay, arada yeni kayıt eklenmesi, tekrar poll ve filtre değişimi.

## Tamamlanma değerlendirmesi

| Özellik | İncelemede görülen durum |
| --- | --- |
| SKY-01 | Tarama karşılaştırması var; sürüm/build verisi yokluğu dürüst etiketli. Remediation değişmiyor. Kapsam satırlarından iki tarafın kanıtlarına doğrudan bağlantı eksik; R2/R3 bunu da etkiliyor. |
| SKY-02 | Profil kanıtları ve ön kontrol ayrımı var; form-login Unknown. R5 nedeniyle durum kararı düzeltilmeli. Atıf isteği gönderen ajana değil, kaydı görüntüleyen ajana ait. |
| SKY-03 | Matris/filtre/kanıt ekranları var. R2/R3 giderilmeden “kanıtlı test kapsamı tamamlandı” denemez. |
| SKY-04 | Kabul / bağlamda / uygulama belirsizliği ayrımı ve hedef ajanın sonraki aktiviteleri mevcut. Önceki native mesajlaşma testleri de geçti. |
| SKY-05 | Görüntü izleme uygulanmış değil: yalnız metadata + withheld/unavailable. Sır koruması açısından dürüst fallback; çalışan canlı tarayıcı özelliği sayılmaz. |
| SKY-06 | Birleştirilmiş görünüm/replay var; R1/R4/R6 önemli. Ajan oluşumu ve durum geçişleri için kalıcı tarihçe de mevcut kaynaklardan tamamlanmış değil. |
| SKY-07 | Kanıt panelleri, maskeli diff/indirme ve şifreli revizyonlu notlar var; testler orijinal kanıtın değişmediğini kontrol ediyor. Bağlı screenshot gösterimi yok. |

Yeni `auth_snapshot` ile başlayan gerçek bir Strix kabul çalışması yapılmadı; bu inceleme de başlatmadı.
Mevcut 124 test R1–R6'yı yakalamıyor. Önce bu kusurların regresyon testleri ve düzeltmeleri, ardından
izinli yerel hedefte yeni kabul çalışması önerilir. Bu rapor tam güvenlik denetimi veya tüm kusurların listesi değildir.
