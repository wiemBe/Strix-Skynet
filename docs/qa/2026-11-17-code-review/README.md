# Uygulama kodu incelemesi — QA

17 Kasım 2026 · sentetik hedef/kampanya · geçici veri dizini/anahtar · lifespan kapalı localhost sunucu.
Asıl veri, worker, scheduler, backfill ve Strix/LLM taraması kullanılmadı.

- [Ayrıntılı inceleme, düzeltilen sorunlar ve sınırlar](../../reviews/2026-11-17-application-code-review.md)
- [Kaynak envanteri ve dosya hash'leri](source-inventory.json)
- [Hedef raporu · 1366×768](report-1366.jpg)
- [Ayrıntılı rapor seçimi · 1920×1080](report-1920.jpg)
- [Kampanya ve ilgili scan geçmişi · 1920×1080](campaign-1920.jpg)
- [Tarama Details sekmesi · 1920×1080](scan-details-1920.jpg)
- [Viewer ayrıntılı rapor ve indirme · 1366×768](viewer-report-1366.jpg)

Rapor/kampanya sayfalarında ölçülen yatay taşma yok. Ayrıntılı raporda 12 bulgu, kampanya scan tablosunda
1 satır doğrulandı. Report→Details değişimi son seçimi korudu; yarış ayrıca kontrollü yanıt sırasıyla Node
regresyon testinde doğrulandı. Browser console warning/error kaydı yoktu. Viewer'da Scan again görünmedi;
Markdown düğmesi dosyayı gerçekten indirdi. Tarayıcı viewport override'ı sonunda sıfırlandı.

Ekranlar geliştirme QA anını gösterir; son küçük dilbilgisi düzeltmesini ayrıca göstermez. PDF dosyası
oluşturulup sayfa sayfa incelenmedi; bu görüntüler PDF kabul kanıtı değildir.

Son kontroller: **246 Python + 2 Node testi geçti**; compileall, JS sözdizimi ve diff whitespace kontrolü temiz.
