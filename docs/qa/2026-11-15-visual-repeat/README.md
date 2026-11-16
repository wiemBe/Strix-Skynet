# Tekrar görsel QA — 15 Kasım 2026

Kullanıcının yeniden görsel QA talebi üzerine uygulama tarayıcıda **1366×768** ve **1920×1080** olarak
kontrol edildi. Testler ayrı DB/anahtar ve yerel geçmiş çıktılarının kopyasıyla localhost:8796'da yapıldı.
Worker, scheduler, recovery ve import başlatılmadı. Yeni Strix/LLM çalışması veya ajan talimatı gönderilmedi.

## Bulunan ve düzeltilenler

| Kusur | Düzeltme | Yeniden kontrol |
| --- | --- | --- |
| 1366'da son Details sekmesi 17 piksel kesiliyordu | Tarama sekmeleri laptop boyutunda 6×2, geniş ekranda tek sıra | 12 düğmenin tamamı sekme kutusunun içinde |
| Oturum tablosunda uzun ajan adı ve kanıt satırları kısaltılıyordu; satırlar sıkışıktı | Metin sarma ve dikey hücre boşluğu | Ajan adı, endpoint/durum/kayıt sayısı okunabiliyor; Open çalışıyor |
| 768 yükseklikte New scan alt eylemleri ekran dışındaydı (alt sınır 1084px) | Pencere viewport ile sınırlandı; gövde kayar, başlık ve alt eylemler sabit | Alt eylemler 743px içinde; Extra instructions alanına gidip Cancel ile kapatıldı |
| Details talimat metni 145px yatay taşma üretiyor, ikinci kart 16px aşağı başlıyordu | Uzun talimat sarılır; kartların üst hizası eşit | İki boyutta sayfa taşması 0, kart üstleri eşit |
| Canlı panelde “Mod” uygulama etiketi kalmıştı | “Mode” | Aktivite paneli ekran görüntülerinde İngilizce |

Değişen kaynaklar: `skynet/static/app.js` ve `skynet/static/style.css`.
İş mantığı, şifreleme, Verify sonuçları ve tarama çalıştırma davranışı değiştirilmedi.

## Kontroller ve kanıtlar

- Taramanın 12 sekmesi: Live activity, Timeline, Findings, Coverage, Session health, Instructions, Browser,
  Live log, Agents, Telemetry, Report, Details; iki çözünürlükte ekran görüntüleri alındı.
- Ajan seçimi aktivite akışını filtreledi. Oturum kanıtının Open/Close akışı ve maskeli request/response penceresi çalıştı.
- Evidence workspace'te 803/804 yanıt farkı, tarama karşılaştırması ve uzun New scan formu incelendi.
  Form yalnız doldurulup iptal edildi; Start scan kullanılmadı. Profil/sır/kanıt/remediation kayıtları düzenlenmedi.
- [browser-checks.json](browser-checks.json): toplam 43 ölçüm, görünüm/boyut başına son 38 kontrol.
  Son kontrollerde **sayfa taşması, kesilen sekme, viewport dışı alt eylem veya JS konsol hatası yok**.
  Önceki Details taşma kaydı tarihsel ölçüm olarak korunur; `latestChecks` düzeltme sonrasını içerir.
- 41 ekran görüntüsü: `before-*` kusur öncesi, diğerleri yeniden kontrol görüntüleridir.
  Tam sayfa görüntüleri viewport yüksekliğinden uzun olabilir; gerçek boyutlar JSON'dadır.
- `node --check` (app.js ve sky.js), `git diff --check` geçti. Bu CSS/etiket düzenlemesi için backend test
  paketi tekrar çalıştırılmadı; önceki RHEL QA test sayısı bu çalışmanın yeni sonucu olarak sunulmaz.

Örnekler: [laptop oturum tablosu](session-1366.jpg), [tarama formu](scan-dialog-1366.jpg),
[formun altı](scan-dialog-scrolled-1366.jpg), [Details](details-1366.jpg), [ajan seçili akış](activity-final-1366.jpg).

## Sınırlar

- Bu tur görsel ve tarayıcı etkileşim QA'sıdır; gerçek canlı Strix ajanı başlatılmadı ve RHEL kabulü tekrarlanmadı.
- Kullanılan gerçek geçmiş kayıtları daha önce izin verilmiş yerel taramalardır. QA kopyası log/report dosyası
  içermediği için bu iki sekmede boş durum kontrol edildi; orijinal çalışmada dosya olmadığı sonucuna varılmadı.
- Kopya DB'deki açıkça “QA fixture — UI polling only” isimli eski sentetik kayıt, sol menüdeki 1 sayacını
  oluşturur. Gerçek çalışan tarama değildir; bu tur onun üzerinde bir eylem yapılmadı.
- Browser hâlâ gerçek görüntü verisi olmayan durumda bunu açıkça belirtir; canlı video desteği iddia edilmez.
- Geçici sunucu kapatıldı. Asıl kurulumun data/anahtarı korunur; commit/deploy yapılmadı.
