# OpenCode Go ve otomatik runtime yolları — QA

18 Kasım 2026. Geçici DB/şifreleme anahtarı, localhost:8794, normal lifespan/worker/scheduler kapalı.
Asıl uygulama verisi ve kayıtlı anahtarlar değiştirilmedi; mevcut servis yeniden başlatılmadı.

## Go bağlantısı

- Provider seçiminde OpenCode Go; doğru Go/OpenAI adresi, varsayılan chat completions, şifreli anahtar.
- Model kataloğu testi için **sentetik** `qa-go-model` / `qa-go-second-model` yanıtı kullanıldı;
  dış bağlantı fixture tarafından engellendi. Ekranlar gerçek Go hesabı/kotası veya çıkarım kabulü değildir.
- Formdan katalog kontrolü, model önerileri, kayıt, kaydedilmiş anahtarla tekrar kontrol, düzenlemede boş
  anahtar alanı, provider değişiminde eski URL/model/anahtar/katalog temizliği doğrulandı.
- Go katalog sonucu hem formda hem Settings satırında “Model catalogue loaded” olarak gösterildi;
  anahtar geçerliliği/çıkarım izni/kota doğrulanmadığı açıkça yazıyor.
- [Form · 1366×768](form-1366.jpg), [katalog sonucu · 1920×1080](catalogue-1920.jpg),
  [kaydedilmiş sentetik profil · 1366×768](saved-1366.jpg).
- 12 yeni Python regresyonu: API şifreleme/yetki, anahtar zorunluluğu ve provider değişimi, ortam izolasyonu,
  Go katalog URL'si/başlıkları ve hata maskelemesi, sabit/resume oturumu, runner config ve launch öncesi
  maskeleme snapshot'ı. Kurulu native Strix ayar parser'ı ve request-header birleştiricisi subprocess içinde
  çalıştırıldı; gerçek model çağrısı yapılmadı.

## Otomatik yollar / manuel override

- Önceki kayıtlı yollar manuel olarak korundu. “Use automatic paths → Save” sonrasında alanlar boş kaldı;
  etkin binary `bundled`, çalışma klasörü `home directory` kaynağıyla gösterildi.
- Her iki yol manuel girilip kaydedildi; sayfa reload sonrasında değerler ve “manual override” kaynağı
  korundu. Ardından otomatiğe dönüldü. QA kaydetmelerinde gerçek TUI geçmişini içe aktarma engellendi.
- [Otomatik yollar · 1366×768](auto-paths-1366.jpg),
  [manuel yollar · 1920×1080](manual-paths-1920.jpg).
- 7 yeni Python regresyonu: binary keşif sırası ve sonradan kurulum, executable kontrolü, ortam/manüel
  önceliği, home/data fallback, salt okunur çözümleme, DB'de boş otomatik değerlerin korunması, Settings API
  kayıt/reset/doğrulama, çalışan taramada workdir değişimi engeli, çözülmüş klasörden geçmiş import yolu.
- Doctor uygulamayla aynı saf resolver'ı kullanır; Skynet konfigürasyonunu import edip dizin oluşturmaz.
  Mevcut 9 deployment testi de geçti.

Her iki boyutta yatay taşma yok; incelenen tarayıcı warning/error kayıtları boş. Laptop formunda gövde
kaydırılırken Test/Cancel/Save düğmeleri görünür kalıyor. Browser viewport override'ı sıfırlandı ve geçici
sekmeler kapatıldı; localhost QA sunucusu durduruldu.

Son doğrulama: **265 Python testi + 2 Node testi geçti**; compileall, JS syntax ve diff whitespace kontrolü
temiz. Mevcut SQLite ResourceWarning ve beklenen unsafe-control fixture uyarısı testleri bozmadı.

## Sonraki gerçek Go kabul kontrolü

Kullanıcının açık isteğiyle, kaydettiği Go anahtarı/modeli üzerinden tek küçük gerçek istek yapıldı.
`glm-5.3-flash`: HTTP 200, streaming 3 olay, beklenen `skynet_connection_test` araç çağrısı ve
`{"status":"ok"}` argümanı doğrulandı. 0,70 sn; 189 giriş/14 çıkış tokenı. Sağlayıcı bu isteği
`billing_source: go`, `cost: 0` olarak bildirdi. Sabit bir kontrol mesajı dışında kullanıcı hedef/tarama
verisi gönderilmedi; anahtar gösterilmedi. Bu sonuç yukarıdaki sentetik ekranlardan ayrıdır; kalan kotayı,
tam Strix taramasını veya sonraki isteklerin ücretlendirmesini doğrulamaz.
