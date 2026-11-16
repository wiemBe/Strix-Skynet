# README ekran görüntüleri

17 Kasım 2026 · Europe/Istanbul · uygulama kaynak sürümü `af7b87b`.

Bu dizindeki altı JPEG, mevcut Skynet arayüzünün headless Chrome / Playwright ile alınmış gerçek
tarayıcı görüntüleridir. Görseller üzerinde arayüz veya veri değişikliği yapılmadı.
1600 × 1050 pencere kullanıldı; yönetim raporu tam sayfa olarak kaydedildi.

| Dosya | Görünüm |
| --- | --- |
| [target-details.jpg](target-details.jpg) | Hedef, kapsam, bulgu grupları ve tarama geçmişi |
| [campaign.jpg](campaign.jpg) | Kampanya, bağlı hedefler ve bulgu özeti |
| [inventory.jpg](inventory.jpg) | Varlık türleri, kapsam ve kanıt düzeyi |
| [auth-profiles.jpg](auth-profiles.jpg) | Vault profili ve hedef atamaları |
| [management-report.jpg](management-report.jpg) | Yazdırılabilir yönetim raporu |
| [audit-log.jpg](audit-log.jpg) | Kullanıcı ve eylem filtreli denetim kaydı |

Uygulama, host veri/anahtarı ve Docker soketi paylaşılmayan geçici UBI 9 konteynerinde çalıştırıldı.
**Demo adları, `.example.test` hedefleri, bulgular, tarama geçmişi ve envanter sentetik dokümantasyon
verileridir.** İşçi ve zamanlayıcı başlatılmadı; hedefe veya LLM sağlayıcısına istek yapılmadı.
Ekrandaki `Docker is down` durumu, bu ortamda Docker soketi paylaşılmamasından kaynaklanır.

1600 × 1050 ve 1366 × 768 genişliklerinde yatay sayfa taşması kontrol edildi. Görüntüler tek tek incelendi;
JavaScript hatası görülmedi ve demo parola/sır değerleri sayfa içeriğinde bulunmadı.
Makine tarafından okunabilir kayıt: [capture-checks.json](capture-checks.json).
