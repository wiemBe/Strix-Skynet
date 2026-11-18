# Üç sağlayıcıda otomatik model seçimi — QA

18 Kasım 2026. Geçici veri/anahtar, lifespan kapalı localhost QA. Go 31, OpenRouter 251, anahtarsız LiteLLM
2 sentetik model; dış katalog/çıkarım çağrıları fixture tarafından engellendi. Gerçek profil modelleri ve
anahtarları değiştirilmedi. Gerçek LLM erişim testi bu kontrolün kapsamı değil; önceki Go testi ayrı kayıtlı.

- **Change model** ile aramaya odaklanma, otomatik katalog yükleme ve kayıtlı modelin korunması doğrulandı.
- Go: `second` araması → 1/31 → `qa-go-second-model` seçimi → Save sonrası `openai/qa-go-second-model`.
  [1366×768](go-1366.jpg).
- OpenRouter: ilk 200 seçenek render edildi, `openai/qa-gpt` kimliğinin vendor öneki korundu.
  `249` araması → ilk 200'ün dışındaki model → `vendor/qa-model-249` → Save sonrası doğru Strix kimliği.
  [1920×1080](openrouter-1920.jpg).
- LiteLLM: anahtar gerekmeden iki gateway deployment'ı yüklendi; klavye/listeden `deployment-b` seçimi
  → Save sonrası `openai/deployment-b`. [1366×768](litellm-1366.jpg).
- Provider Go'ya çevrilince eski liste/model/adres/anahtar temizlendi; yeni Go anahtarı olmadan sorgu
  başlatılmadı ve nedenini açıklayan durum metni gösterildi. Geç yanıt, yeni listeyi değiştiremiyor.
- İki viewport'ta yatay taşma yok; modal gövdesi kaydırılabiliyor, alt Save/Cancel/Test eylemleri görünür.
  Son localhost oturumunda browser warning/error kaydı yok. İlk 127.0.0.1 QA oturumu farklı porttaki gerçek
  uygulamayla cookie alanını paylaştığı için düşmüştü; kalan QA ayrı `localhost` host'unda tamamlandı.

Son kontroller: **273 Python + 7 Node testi geçti**, compileall / JS syntax / diff-check temiz.
8 yeni backend regresyonu: public OpenRouter kataloğunda key/inference çağrısı yok, gereksiz decrypt yok,
Go kayıtlı anahtar ve yeni adres izolasyonu, provider değişimi, LiteLLM /v1 keşfi, RBAC ve model kaydı.
5 yeni frontend regresyonu: eski response/error, kapanan form, tek/çok model otomatik seçim davranışı,
bekleyen sorgu sırasında elle model değişimi, sağlayıcıya göre doğru model öneki.

Geçici QA sunucusu durduruldu. Kullanıcının yan panel testi için açılmış gerçek localhost:8787 preview,
güncel kodla yeniden açıldı; önceki gibi lifespan/worker/scheduler kapalı. Yeni migration, tarama veya
ücretli çıkarım yapılmadı. Commit/push yok.

Son olarak gerçek yan panel uygulaması yenilendi; kullanıcının kayıtlı Go bağlantısında yeni seçici
**31 gerçek model** getirdi ve `glm-5.3-flash` mevcut seçimini korudu. Form açık bırakıldı, Save'e basılmadı;
gerçek profil değiştirilmedi. Bu son kontrol yalnız katalog GET isteğidir, çıkarım değildir.
