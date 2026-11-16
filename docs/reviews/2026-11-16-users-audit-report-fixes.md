# Kullanıcı, audit ve rapor düzeltmeleri — 16 Kasım 2026

Başlangıç commit'i `4f04aa2`, branch `users-roles-audit-report`.
[İncelemede](2026-11-16-users-audit-report-review.md) bulunan R1–R5 kapatıldı.
Uygulama kodu, regresyon testleri ve görsel QA kanıtları çalışma ağacında; commit/merge/push yapılmadı.

| Bulgu | Son davranış | Doğrulama |
|---|---|---|
| R1 — Audit sırrı | Serbest metadata saklanmadan ve kesilmeden önce maskeleniyor. Güncel Vault + saklanan tarama sırları kullanılıyor; okuma yeniden maskeleniyor. | Gerçek mesaj API/auth/audit yolu; yalnız Strix'e gönderme taklit edildi. DB/API'de test sırrı yok. Profil silindikten sonra eski tarama sırrı da maskeli. |
| R2 — Eski oturum | Disable oturum sürümünü artırıyor; re-enable eski çerezi canlandırmıyor. Migration, önceden kapalı hesapları da kapsıyor. | Eski çerez 401; yeniden girişle üretilen güncel çerez 200. İki kapatma/açma çevrimi ve v6→v7 geçişi. |
| R3 — Düzeltme süresi | `fixed_at` yalnız Fixed'e geçişte yazılıyor. Aynı durumdaki not değişikliği geçiş zamanını değiştirmiyor. Reopen temizliyor; tekrar Fixed yeni zamanı kullanıyor. | Not düzenlemesinden önce/sonra medyan 1 gün. Reopen/tekrar fix ve belirsiz eski kayıt testleri. |
| R4 — Rapor metadata | Hedef/kampanya metadata'sı, trend/coverage metinleri ve hazırlayan adı dahil bütün rapor maskeli. Açıklama kesilmeden önce maskeleme uygulanıyor. | Viewer rapor API'leri; silinen profilden kalan scan snapshot'ı; 200 karakter sınırına gelen sır için prefix kontrolü. |
| R5 — Viewer eylemleri | Workspace mutasyonlarına açık Analyst yetkisi verildi; Viewer'da yeni not editörü yok. Mevcut not/revizyon/kanıt okuma ve fark görünümü kullanılabilir. | Gerçek Viewer ve Analyst oturumlarıyla iki viewport'ta etkileşimli QA. Backend tüm mutasyonlarda Viewer'ı hâlâ reddediyor. |

Görsel QA'da iki ek sorun kapatıldı:

- Yalnız Control rolü atanmışken iki varsayılan panel aynı isteği seçebiliyordu. İkinci farklı kayıt varsa
  seçimler farklı kalıyor. Bu yalnız görüntüleme seçimi; kalan kayda Attack rolü atanmıyor, yeni istek gönderilmiyor.
- Rol açıklaması iki satıra sarıldığında kanıt kartları farklı yükseklikten başlıyordu. Paylaşılan grid satırları
  panel üstlerini hizalıyor; tek sütun düzeninde normal dikey akış korunuyor. Son 1366px ölçümünde iki üst kenar
  da `421.09375px`.

## Migration ve veri anlamı

Migration 7: `users.session_version` ve nullable `finding_groups.fixed_at`.
Mevcut SQLite backup API mekanizması ilk pending migration öncesi tutarlı, 0600 yedek alıyor.
Şifreleme anahtarı yeniden üretilmiyor/değiştirilmiyor. İncelemede asıl DB migration'ı çalıştırılmadı;
tüm migration testleri geçici DB/anahtarla yapıldı.

Eski `remediation_at`, not düzenlenince de değişebildiği için güvenilir fix zamanı sayılmıyor.
Eski fixed kayıtlar fixed kalır; sayı ve orijinal kanıt korunur. Zamanı bilinmeyenler süre metriğinden çıkarılır,
sıfıra çevrilmez; rapor kaç kaydın çıkarıldığını açıklar. Hiçbir doğrulama otomatik fixed yapmıyor.

V7 gizlilik onarımı eski audit metadata'sındaki o anda bilinen tam sır değerlerini maskeler; event id/zaman/sonuç
korunur. Tarihsel yedekler değiştirilmez ve eski açık metadata içerebilir. Sonradan öğrenilen değerler okuma
sırasında da maskelenir. Bilinmeyen sırları maskeleme garantisi yoktur; okunamayan saklı maskeleme verisi varsa
yeni audit kaydını maskelemesiz yazmak yerine işlem hata verir.

## Kabul kanıtı

- **183/183 test geçti**; 9 yeni regresyon testi. JS sözdizimi ve `git diff --check` geçti.
- [Tekrar üretim çıktısı](../qa/2026-11-16-users-fixes/reproductions.json): DB/API'de sır yok; eski çerez 401;
  not değişikliğinde 1 gün → 1 gün; raporda test sırrı yok.
- [Görsel QA](../qa/2026-11-16-users-fixes/README.md): 32 ekran görüntüsü, 1366×768 ve 1920×1080.
  Admin Settings/users, Add user/Change role formları, Audit, hedef/kampanya raporları,
  Analyst/Viewer workspace, notlar/revizyonlar, fark ve Viewer Settings/boş rapor.
- Ölçülen görünüm ve dialog'larda yatay sayfa taşması/kesilen alt eylem görülmedi; browser warning/error yok.
- Yalnız sentetik, açıkça QA fixture'ı olarak etiketlenmiş yerel kayıtlar. Normal lifespan, worker, scheduler,
  import/recovery ve gerçek Strix/LLM taraması başlatılmadı. Test suite'in native bridge kontrolleri yalnız
  yerel koordinatör/oturum fixture'larıdır; dış hedef taraması değildir.
- Bu turda gerçek PDF üretimi veya yeni RHEL/systemd/SELinux kabulü yapılmadı. Önceki RHEL sunucu kabulü bekliyor.
