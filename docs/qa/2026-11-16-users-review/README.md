# Kullanıcı, audit ve rapor QA — 16 Kasım 2026

> Düzeltme öncesi tarihsel kanıtlar. R1–R5'in son durumu ve tekrar QA:
> [2026-11-16-users-fixes](../2026-11-16-users-fixes/README.md).

Commit `4f04aa2`, macOS yerel inceleme. [Ayrıntılı bulgular](../../reviews/2026-11-16-users-audit-report-review.md).
**Açık: R1/P1, R2–R4/P2, R5/P3. Uygulama kodunda düzeltme yapılmadı.**

- [174 testin çıktısı](tests.txt).
- [İzole tekrar üretim sonuçları](reproductions.json),
  [çalıştırılabilir betik](../../reviews/reproduce_users_audit_issues.py).
- [Browser ölçümleri ve sınırlar](browser-checks.json).

Tarayıcı kendi geçici veritabanı ve anahtarıyla 127.0.0.1:8797'de çalıştı.
Kullanıcılar ve bulgular sentetik QA fixture'larıydı; çalışan Strix ajanı veya gerçek tarama değildi.
Normal uygulama lifespan'ı devre dışıydı: worker/scheduler/recovery/import başlatılmadı.
Asıl veri/anahtara dokunulmadı; yeni pentest, provider isteği, PDF üretimi ve RHEL testi yapılmadı.
QA sunucusu inceleme sonunda kapatıldı.

## Görsel kanıtlar

| Ekran | 1366×768 | 1920×1080 |
|---|---|---|
| Admin Settings / users | [Görüntü](admin-settings-1366.jpg) | [Görüntü](admin-settings-1920.jpg) |
| Audit | [Görüntü](audit-1366.jpg) | [Görüntü](audit-1920.jpg) |
| Admin report | [Görüntü](report-1366.jpg) | [Görüntü](report-1920.jpg) |
| Viewer evidence workspace | [Görüntü](viewer-workspace-1366.jpg) | [Görüntü](viewer-workspace-1920.jpg) |
| Viewer report | [Görüntü](viewer-report-1366.jpg) | [Görüntü](viewer-report-1920.jpg) |

[Viewer Settings](viewer-settings-1366.jpg).
[Viewer'ın görünen eylemine sunucunun verdiği yetki hatası](viewer-denied-action-1920.jpg).
Ekrandaki “Evidence gap” fixture'ın kaynak run klasörü olmamasından; “No LLM connection” sağlayıcı
tanımlanmamasından kaynaklanır. Bunlar bu incelemenin ürün kusurları değildir.

Sayfa genelinde yatay taşma ve browser warning/error görülmedi. Raporlar kaydırılabilir;
tam sayfa yakalamadaki boş alan tek başına ürünün içerik kırptığına kanıt sayılmadı.
PDF düzeni gerçek bir PDF üretilerek doğrulanmadı.
