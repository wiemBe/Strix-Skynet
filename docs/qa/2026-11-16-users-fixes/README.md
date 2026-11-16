# Kullanıcı/audit/rapor düzeltmeleri — görsel QA

16 Kasım 2026 · macOS · yerel browser · 1366×768 / 1920×1080.
[Düzeltme raporu](../../reviews/2026-11-16-users-audit-report-fixes.md).

**183/183 test geçti; R1–R5 kapatıldı.** Görsel QA'da varsayılan istek seçimi ve kart hizası da düzeltildi,
ekranlar yenilenerek yeniden kontrol edildi. 32 JPEG kanıt kaydedildi.

- [Tam test çıktısı](tests.txt), [izole tekrar üretimler](reproductions.json), [browser ölçümleri](browser-checks.json).
- [Tekrar üretim betiği](../../reviews/reproduce_users_audit_issues.py).
- [Geçici UI fixture sunucusu](serve_fixture.py): `.venv/bin/python docs/qa/2026-11-16-users-fixes/serve_fixture.py`.
  Kendi temp DB/anahtarını üretir; 127.0.0.1:8797'de çalışır. Normal lifespan tamamen değiştirilmiştir;
  worker/scheduler/Strix/provider çağrısı yoktur. Test hesapları ve kayıtlar sentetiktir.

| Görünüm | 1366×768 | 1920×1080 |
|---|---|---|
| Admin users | [Ekran](admin-users-1366.jpg) | [Ekran](admin-users-1920.jpg) |
| Add user (yalnız aç/cancel) | [Ekran](add-user-dialog-1366.jpg) | [Ekran](add-user-dialog-1920.jpg) |
| Change role (yalnız aç/cancel) | [Ekran](change-role-dialog-1366.jpg) | [Ekran](change-role-dialog-1920.jpg) |
| Audit | [Ekran](admin-audit-1366.jpg) | [Ekran](admin-audit-1920.jpg) |
| Audit actor + Enter araması | [Ekran](audit-search-1366.jpg) | [Ekran](audit-search-1920.jpg) |
| Hedef raporu | [Ekran](target-report-1366.jpg) | [Ekran](target-report-1920.jpg) |
| Kampanya raporu | [Ekran](campaign-report-1366.jpg) | [Ekran](campaign-report-1920.jpg) |
| Analyst workspace | [Ekran](analyst-workspace-1366.jpg) | [Ekran](analyst-workspace-1920.jpg) |
| Analyst not revizyonu | [Ekran](analyst-note-revision-1366.jpg) | [Ekran](analyst-note-revision-1920.jpg) |
| Analyst response farkı | [Ekran](analyst-diff-1366.jpg) | [Ekran](analyst-diff-1920.jpg) |
| Viewer workspace (son hizalama) | [Ekran](viewer-workspace-1366.jpg) | [Ekran](viewer-workspace-1920.jpg) |
| Viewer notları | [Ekran](viewer-notes-1366.jpg) | [Ekran](viewer-notes-1920.jpg) |
| Viewer Settings | [Ekran](viewer-settings-1366.jpg) | [Ekran](viewer-settings-1920.jpg) |
| Viewer boş/uzun adlı rapor | [Ekran](viewer-empty-report-1366.jpg) | [Ekran](viewer-empty-report-1920.jpg) |

Ek: [rapor altı](target-report-footer-1366.jpg), [kampanya hedef tablosu](campaign-report-targets-1920.jpg),
[Viewer fark](viewer-diff-1920.jpg), [login](login-1366.jpg).

Analyst ile not ekleme/revizyon, korelasyon onayı, Control etiketi ve response farkı çalıştı.
Viewer'da mutasyon eylemleri/yeni not alanı yok; kanıt/not/revizyon ve fark okunabilir.
Maskeli audit/rapor metadata'sı görünür; belirsiz fix zamanı sıfıra dönüşmez. Sayfa genelinde yatay taşma,
dialog alt eylemlerinde kesilme veya browser warning/error görülmedi.

Kampanya fixture'ına tarama bağlanmadığından kampanya raporu sıfır kayıt gösterir; üye hedefin bağımsız
taramasını kampanyanın çalışması saymaz. Hedef raporunda ayrı tarama/bulgu kayıtları vardır.
Eksik coverage.json Unknown olarak açıklanır; bu fixture'ın çalıştırılmamış motor kaydı olmasıyla tutarlıdır.

Asıl veri/anahtar değiştirilmedi; test sunucusu kapatıldı ve yalnız kendi geçici klasörleri temizlendi.
Gerçek PDF üretilmedi, bu turda RHEL yeniden çalıştırılmadı. Yeni migration yalnız fixture DB'lerde denendi.
