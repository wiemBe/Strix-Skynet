# Kullanıcı, audit ve yönetim raporu incelemesi — 16 Kasım 2026

> Bu ilk incelemenin tarihsel kaydıdır. R1–R5 daha sonra
> [düzeltildi ve yeniden doğrulandı](2026-11-16-users-audit-report-fixes.md).
> Aşağıdaki “açık / kod değiştirilmedi” ifadeleri ilk inceleme anını anlatır.

İncelenen commit: `4f04aa2ae27e20445e7f8e0337e22762ee1330fc`, branch `users-roles-audit-report`.
Karşılaştırma tabanı: `253dbc61fbf084539c8a129b60f3a25b1cdaaf0c`.
Yeni kapsam: kullanıcı/rol yönetimi, merkezi API yetkilendirmesi, audit kayıtları ve yönetim raporu.

174 mevcut test geçti. Aşağıdaki beş kusur açık; bu inceleme özellik kabulü değildir.
Uygulama kodu değiştirilmedi, merge/push yapılmadı. Önceki düzeltme ve RHEL kabul sınırları devam ediyor.

## R1 / P1 — Audit özeti bilinen Vault sırrını açık metin saklıyor

Kaynak: `skynet/audit.py:134–141`, `skynet/main.py:823–834`.
Mesaj gönderme handler'ı ajan adını doğrudan audit özetine koyuyor. Merkezi yazıcı yalnız uzunluğu kesiyor;
bilinen sırları maskelemiyor. Okuma yolu da kayıtları doğrudan döndürüyor (`audit.py:157–161`).

İzole fixture'da güncel Vault header sırrını içeren ajan adı kullanıldı. Normal scan redactor aynı adı
maskelerken HTTP 200 ile sonuçlanan talimat yolundan sonra sır hem SQLite audit kaydında hem audit okuma
sonucunda bulundu. Yalnız `control.send` sahte yanıtla değiştirildi; gerçek auth, route ve audit middleware çalıştı.
Gerçek Strix ajanına talimat gönderilmedi. Mesaj metninin loglanmaması, ajan adının güvenli olduğu anlamına gelmiyor.

Audit için tercihen sabit eylem ve nesne kimlikleri saklanmalı; serbest metin gerekiyorsa ilgili tarama/bulgu
maskeleme bağlamıyla **kalıcılaştırmadan önce** temizlenmeli. Mevcut audit kayıtlarının okunması ve daha sonra
öğrenilen sırlar da ele alınmalı. Aksi halde sır SQLite ve yedeklerinde kalır.

## R2 / P2 — Hesabı yeniden açmak eski oturum çerezini yeniden geçerli yapıyor

Kaynak: `skynet/auth.py:176–186`, `247–250`, `274–275`.
Devre dışı bırakma yalnız `active` alanını değiştiriyor; oturum parmak izi kimlik ve parola temelli.
Test: önceden alınmış çerezle hesabı kapattıktan sonra `/api/me` 401; aynı hesabı açınca **aynı çerezle** 200.
Yeni login gerekmiyor. Kapalıyken erişim doğru engelleniyor; kusur eski oturumun yeniden canlanması.

Arayüzün hesabı kapatmanın hemen çıkış yaptırdığı vaadiyle uyumsuz. Şüpheli bir oturumu kapatmak amacıyla
askıya alınan hesap, tekrar açıldığında bu oturuma yeniden erişim verir. Kalıcı oturum sürümü/iptal zamanı
kullanılmalı; kapatma eski oturumları geri döndürülemez şekilde geçersiz kılmalı.

## R3 / P2 — Not düzenlemek rapordaki düzeltme süresini değiştiriyor

Kaynak: yeni metrik `skynet/report.py:94–97`; mevcut güncelleme yolu `skynet/main.py:1352–1353`.
Rapor, değişebilir `remediation_at` alanını düzeltmenin tamamlanma zamanı olarak kullanıyor.
Handler ise durum aynı kalsa bile not kaydedilince bu zamanı yeniliyor.

Test: 1 Ocak ilk görülme, 2 Ocak fixed → medyan 1 gün. 10 Ocak'ta yalnız not değiştirildi, durum fixed
kaldı → medyan **9 gün**. Yeni rapor, önceden mevcut yazma davranışından yanlış iş metriği türetiyor.
Durum geçişi için sabit bir zaman/olay saklanmalı; aynı durumdaki not düzenlemesi bu zamanı değiştirmemeli.
Geçmiş verinin gerçek geçiş zamanı belirlenemiyorsa ölçüm bilinmiyor olarak kalmalı.

## R4 / P2 — Rapor başlığındaki metadata sır maskelemesini atlıyor

Kaynak: `skynet/report.py:129–130`, kampanya için `149–152`.
Üst bulgular redactor'dan geçerken hedef adı/URL, kampanya adı/açıklaması ve hedef satırları ham dönüyor.
Test: hedef adı güncel Vault sırrını içerdiğinde Viewer'ın hedef raporu isteği 200 döndü ve rapor JSON'unda
sır aynen bulundu. Arayüz bu metadata'yı yazdırılabilir raporda kullanıyor.

Raporun tamamı ilgili hedef/taramaların maskeleme bağlamıyla sunulmalı; yalnız bulgu listesi yeterli değil.
Bu test PDF üretmedi: doğrulanan sonuç API çıktısı ve bu alanların yazdırılabilir DOM'a aktarılma yolu.
Bu bir yetki atlama veya HTML enjeksiyonu bulgusu değil; raporun maskeleme sözleşmesi ihlalidir.

## R5 / P3 — Viewer'a kullanamayacağı düzenleme eylemleri gösteriliyor

Kaynak: `skynet/static/app.js:109–116`, `166–169`; evidence workspace çağrıları `skynet/static/sky.js`.
Etiket tabanlı yetki haritası `Confirm match`, `Reject match`, `Clear` gibi mutasyonları kapsamıyor.
Gerçek Viewer oturumunda bu düğmeler ve yeni not editörü görünür. `Confirm match` tıklaması sunucudan
403 ve Analyst erişimi gerektiği mesajını verdi. Backend yetki kontrolü çalışıyor; sorun salt okunur arayüz.

Mutasyon çağrıları açık `need: "analyst"` yetkisi taşımalı; Viewer not editörü de gizlenmeli veya salt okunur
olmalı. Düğme metnine dayalı harita, yeni ekranlarla kolayca eksik kalıyor.

## Doğrulama ve sınırlar

- `.venv/bin/python -m unittest discover -s tests`: **174/174 OK**.
- `node --check skynet/static/app.js`, `node --check skynet/static/sky.js`, `git diff --check`: geçti.
- `.venv/bin/python docs/reviews/reproduce_users_audit_issues.py`: R1–R4 izole tekrar üretimleri.
- Tarayıcıda 1366×768 ve 1920×1080: admin Settings, Audit, report; Viewer workspace ve report.
  Viewer kendi Settings ekranı 1366×768'de ayrıca incelendi. R5 etkileşimle doğrulandı.
- Ölçülen sayfalarda yatay taşma ve browser warning/error görülmedi. Görsel kalite kontrolü,
  role özgü eylemlerin işlevsel kabulü veya tüm ürünün uçtan uca kabulü yerine geçmez.
- Yalnız geçici DB/anahtar ve açıkça fixture olarak etiketlenmiş sentetik kullanıcı/bulgu kayıtları kullanıldı.
  Gerçek veri/anahtar, migration veya mevcut süreçler değiştirilmedi. Worker, scheduler, Strix, sağlayıcı
  ve dış hedef çalıştırılmadı. Yeni Linux/RHEL testi yapılmadı; önceki sunucu kabulü bekliyor.

[QA kanıtları](../qa/2026-11-16-users-review/README.md),
[tekrar üretme betiği](reproduce_users_audit_issues.py).
