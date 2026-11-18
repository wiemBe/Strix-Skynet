# Rapor oluşturma iyileştirmeleri — 17 Kasım 2026

Hedef ve kampanya yönetim raporlarına yönetici özeti, öncelikli aksiyonlar, özet/ayrıntılı görünüm ve Markdown
indirme eklendi. Ayrıntılı rapor tüm durumlarıyla bulgu listesini, güncel kapsamı, analist notlarını ve seçili
taramalara ait kaynakları içeriyor. Ek model çağrısı veya yeni bağımlılık yok.

## Doğrulama

- `tests/test_report_generation.py`: 10 regresyon testi; tüm durumlar, altı bulguluk özet sınırı, seçime ait
  görülme sayıları, kampanyadan çıkarılan hedefin eski taramaları, 5.000 taramayı aşan geçmiş, tarih/saat dilimi
  sıralaması, belirsiz/ters tarihler, tarihsel sır maskeleme, Viewer yetkisi/audit ve güvenli Markdown metni.
- Tam test takımı: **224 test geçti**. Bridge ve SIEM testlerinin yalnızca localhost üzerinde açtığı geçici
  soketler nedeniyle sandbox dışındaki test çalıştırıcısı kullanıldı. Mevcut SQLite ResourceWarning mesajları
  testleri başarısız kılmadı. JS sözdizimi ve `git diff --check` temiz.
- Gerçek uygulama API'si ve UI'siyle izole, geçici veritabanında 16 bulgulu hedef/kampanya raporları incelendi.
  Varsayılan tarayıcı penceresi 934px; özet/ayrıntılı seçim çalıştı, ayrıntılı görünümde 16 kayıt bulundu,
  sayfa yatay taşmadı ve console warning/error kaydı yoktu.
- Markdown düğmesi tarayıcıdan gerçekten indirildi; dosya adı `skynet-target-1-report.md`, Türkçe/UTF-8,
  kapsam ve tüm bulgu listesi doğrulandı. API'nin JSON varsayılanı korundu.
- Yazdırma CSS'i ayrıntılı eki yeni sayfadan başlatıyor, uzun tablo bölümlerinin sayfalara yayılmasına izin
  veriyor ve dışa aktarma araçlarını gizliyor. **PDF dosyası üretilip sayfa sayfa incelenmedi:** gömülü
  tarayıcıdaki yazdırma düğmesi otomasyonu zaman aşımına uğradı. Bu kontrol tamamlanmış PDF QA sayılmaz.

## Örnek önizlemeler

Geliştirme sırasında sentetik QA kayıtlarıyla alınmıştır; gerçek hedef veya tarama sonucu değildir.

- [Hedef raporu](target-preview.jpg)
- [Kampanya raporu](campaign-preview.jpg)

Normal lifespan, scheduler, recovery ve Strix/LLM taraması başlatılmadı; gerçek uygulama veritabanı ve
kimlik profilleri değiştirilmedi. Yönetici özeti yalnızca kaydedilmiş verilerden deterministik üretiliyor;
güvenlik skoru veya doğrulanmamış düzeltme sonucu uydurulmuyor.
