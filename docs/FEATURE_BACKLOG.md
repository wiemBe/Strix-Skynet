# Skynet — kullanıcı tarafından seçilen özellikler

Karar tarihi: 15 Kasım 2026 · Europe/Istanbul

**Durum: Geliştirilecek ürün kapsamı olarak kabul edildi. Bu dosya uygulama veya test sonucu değildir.**
Kullanıcı aşağıdaki yedi özelliği seçti ve amaçlarıyla birlikte Claude'un geliştirme sırasında kullanacağı
kalıcı bir not istedi. Bu değişiklik yalnızca dokümantasyondur; özelliklerin kodlanmış olduğu anlamına gelmez.
Gerçek geliştirme ve doğrulama durumu [PROGRESS.md](../PROGRESS.md) içinde tutulur.

## Geliştiren kişi için başlangıç kuralları

- Önce repository talimatlarını, güncel kaynak kodunu, testleri ve son commitleri incele.
  Devir dosyasındaki eski durumları güncel gerçek kabul etme.
- Her özellikte önce mevcut, eksik ve hatalı davranışı ayır. Çalışan işlevleri yeniden yazma.
- Strix pentest motoru ve ajan orkestrasyonu olarak kalır. Yeni bir ajan sistemi kurma.
- Arayüz **İngilizce**; varsayılan saat dilimi **Europe/Istanbul**. Bu dokümanın Türkçe olması UI kararı değildir.
- Koyu kömür ve ölçülü amber tasarım korunur. Sahte veri, dekoratif grafik veya uydurma ilerleme üretme.
- “Bilinmiyor”, “gözlemlenmedi”, “test edilmedi” ve “başarısız” birbirinden farklıdır.
  Eksik ölçümü sıfır, eksik bulguyu giderildi, görünür aktiviteyi başarı olarak yorumlama.
- Kanıtın kaynağı, ilgili tarama/ajan, olay zamanı ve varsa kayda alınma zamanı izlenebilir olmalı.
  Tekrar import/poll/recovery olayları ve sayaçları çoğaltmamalı.
- Sırlar API, rapor, log, profil snapshot'ı ve ekran görüntülerinde korunmalı.
  Migration öncesi mevcut tutarlı backup mekanizmasını kullan; şifreleme anahtarını yenileme.
- Testler izin verilmiş yerel hedeflerde yapılır. Eski dış hedefleri yeniden başlatma.
- UI değişiklikleri 1366×768 ve 1920×1080'de ekran görüntüsü alınıp incelenmeden tamamlanmış sayılmaz.
- Unit/fixture testleri yararlıdır; gerçek Strix kabul çalışmasının yerine geçtiğini iddia etme.
  Tamamlanma kaydında hangi testin fixture, hangi kontrolün gerçek çalışma olduğunu belirt.

## Özellik listesi

| ID | Özellik / önerilen İngilizce ad | Amaç | Başlangıç notu |
| --- | --- | --- | --- |
| SKY-01 | Sürüm karşılaştırması / Release comparison | Sürümler ve taramalar arasındaki güvenlik değişimini görmek | Envanterde mevcut run_diff var; tam release karşılaştırmasıyla eşdeğer sayma |
| SKY-02 | Oturum sağlığı / Session health | Testlerin hangi kimlikle ve ne kadar süre geçerli oturumla yapıldığını görmek | Vault ön kontrolü mevcut; tarama boyu oturum kanıtı değil |
| SKY-03 | Kanıtlı kapsam / Test coverage | Endpoint × rol × test türü için neyin gerçekten test edildiğini göstermek | Mevcut coverage çıktısını kanıt yönünden incele |
| SKY-04 | Ajan talimat merkezi / Agent instructions | Kullanıcı talimatını, kabulünü ve ardından gelen aktiviteleri birlikte izlemek | control.py, strix_bridge.py ve mesaj UI'si mevcut; bunları genişlet |
| SKY-05 | Canlı tarayıcı / Browser view | Seçilen ajanın gerçekten sunduğu tarayıcı görüntüsünü izlemek | Native kaynak/capability doğrulanacak; koşullu özellik |
| SKY-06 | Olay geçmişi / Timeline & replay | Canlı ve tamamlanmış çalışmanın olaylarını zaman üzerinden incelemek | activity.py ve mesaj geçmişi mevcut; ortak zaman çizelgesi geliştirilecek |
| SKY-07 | Kanıt çalışma alanı / Evidence workspace | Bulguyu saldırı/kontrol kanıtları ve analist notlarıyla değerlendirmek | Bulgu/Verify kanıt okuma yollarını koruyup genişlet |

Yukarıdaki başlangıç notları 15 Kasım kaynak incelemesine dayanır; özellik kabulü veya kapsamlı kod denetimi değildir.

## SKY-01 — Sürüm bazlı güvenlik karşılaştırması

**Amaç:** “Önceki sürüm/taramaya göre ne değişti, nerede belirsizlik var?” sorusuna cevap vermek.

Beklenen davranış:

- Kullanıcı referans taramayı ve karşılaştırılacak taramayı seçer. Sürüm/build/commit bilgisi varsa gösterilir;
  yoksa tarama karşılaştırması olarak etiketlenir, sürüm bilgisi uydurulmaz.
- Yeni gözlemlenen endpoint'ler, yeni bulgu gözlemleri, tekrar görülen bulgu adayları ve bu çalışmada
  gözlemlenmeyen önceki kayıtlar ayrı gösterilir. “Yeni”, seçili referansa göredir.
- Kapsam ve profil/rol değişiklikleri, yarım kalan tarama ve farklı test kapsamı görünür olur.
  İlgisiz hedef/ortamları sessizce eşdeğer karşılaştırma.
- Önce test edildiği kanıtlı olup bu kez yürütüldüğü kanıtlanamayan alanlar “Not tested in this run”
  veya kanıta uygun başka bir belirsizlik durumuyla gösterilir. Sadece endpoint kaydının yokluğu yeterli değildir.
- Her değişimden iki taramadaki kaynak gözlemlere ve kanıtlara gidilir.
- Parmak izi eşleşmesi aday ilişkilendirmedir. Analistin doğruladığı eşleştirme ile algoritmik aday ayrışır.

Kabul ölçütleri:

- [ ] Referansta bulunan, yeni çalışmada bulunmayan açık otomatik giderilmiş sayılmaz; remediation durumu değişmez.
- [ ] İptal edilmiş/eksik tarama, azaltılmış kapsam ve farklı roller açıkça görünür; yanıltıcı iyileşme skoru üretmez.
- [ ] Aynı veriyi yeniden içe aktarmak yeni değişim kaydı veya bulgu üretmez.
- [ ] Mevcut `inventory.run_diff` ve bulgu occurrence verileri uygun yerlerde yeniden kullanılır.

## SKY-02 — Tarama boyunca oturum sağlığı

**Amaç:** Bir ajanın yetkili alanları gerçekten test edip etmediğini ve oturumu ne zaman kaybettiğini görmek.

Beklenen davranış:

- Her kullanılan profil/rol için “Session verified”, “Session lost”, “Unknown” durumu,
  son kanıt zamanı ve ilgili ajan/test bağlantısı gösterilir. Anonim profil “Not applicable” olarak ayrılır.
- Durum yalnız belirli bir olay/an için kanıttır. Ayrı ajanların ayrı oturumları olabileceği dikkate alınır;
  bir ajanın başarısı aynı profili kullanan bütün ajanlara veya tüm zamana uygulanmaz.
- Login ekranına yönlenme, kimlik kontrolü, 401/403 gibi sinyaller kaynaklarıyla değerlendirilir.
  HTTP 200 oturum kanıtı değildir; 403 de tek başına oturum kaybı değildir, yetki reddi olabilir.
- Canlı ekranda değişim görünür ve olay geçmişine bağlanır. Yeni kanıt yoksa “Unknown”/eski kanıt bilgisi gösterilir.
  Periyodik aktif kontrol eklenirse açıkça tanımlanır; kendi kendine tekrar login veya sınırsız istek üretmez.
- Verify sınıflandırması yalnız ilgili test/probe/kontrol sırasında geçerli kimlik kanıtını kullanır.
  Ön kontrol başarısı veya paneldeki genel son durum, tarama boyunca korunmuş oturum kanıtına dönüşmez.

Kabul ölçütleri:

- [ ] Form-login başarısı doğrulanamayan negatif deneme `inconclusive` kalır.
- [ ] Başarılı ön kontrol sonrası oturum kaybı ve ajanlar arasında farklı oturum durumu test edilir.
- [ ] Oturum göstergesi hangi kanıta ve hangi zamana ait olduğunu kullanıcıya açar; sırları göstermez.

## SKY-03 — Kanıta bağlı test kapsamı

**Amaç:** Gerçekte yürütülen testleri, yalnız keşfedilen veya planlanan alanlardan ayırmak.

Beklenen davranış:

- Endpoint × rol × test türü matrisi; endpoint, rol, test türü ve durum filtreleri.
- Durumlar: “Tested”, “Partially tested”, “Access blocked”, “Not tested”, “Not applicable”.
  Eksik bilgi ve uygulanabilirliği belirsiz kayıtlar ayrıca “Unknown” olarak ayrılır.
- “Tested” için ilgili testin yürütülmesini destekleyen kayıt gerekir; tek HTTP isteği veya ajanın
  “test ettim” cümlesi yeterli değildir. “Tested” açık bulunmadığı veya uygulamanın güvenli olduğu anlamına gelmez.
- Her hücre ilgili kanıt, ajan, zaman ve gerekçeye açılır. “Not applicable” kararı da gerekçelendirilir.
- OWASP WSTG test kategorileri kullanılabilir; seçilen rehber sürümü/kimlikleri sabitlenir.
  Referans: https://wstg.owasp.org/ . Matristen otomatik OWASP uyumluluk/sertifikasyon iddiası çıkarılmaz.
- Rol ile Vault profil kimliği ayrışır; sır içermeyen rol/profil referansı korunur.
  Keşfedilen her endpoint için bütün test türleri otomatik uygulanabilir varsayılmaz.

Kabul ölçütleri:

- [ ] Her “Tested” hücresinden doğrulanabilir test kanıtına gidilebilir; kanıt yoksa bu durum verilemez.
- [ ] Erişim engeli ile hiç denenmemiş test, kısmi test ile tamamlanan test ayrı kalır.
- [ ] Kaynak coverage.json iddiaları ve Skynet'in kanıt değerlendirmesi ayrı korunur; orijinal çıktı değiştirilmez.
- [ ] Matris sürüm karşılaştırmasında test kapsamı değişimlerinin kaynağı olarak kullanılabilir.

## SKY-04 — Ajan talimat merkezi

**Amaç:** Bir ajana gönderilen talimatın nereye kadar ulaştığını ve ardından ne gözlemlendiğini izlemek.

Mevcut temel: `skynet/control.py`, `skynet/strix_bridge.py`, `/api/scans/{sid}/messages`,
şifreli mesaj geçmişi ve Live activity composer. Bunları inceleyip genişlet; yeni bir paralel mesaj altyapısı kurma.

Beklenen davranış:

- Ajan bazında filtrelenebilir talimat geçmişi; gönderim, kabul ve bağlama eklenme zamanları/gerekçeleri.
- “Queued”/Strix kabulü, “In agent context” ve “uygulandığına dair kanıt” farklı kavramlardır.
  Mevcut backend `delivered` durumunu “ajan uyguladı” olarak yeniden etiketleme.
- Bir talimattan o ajanın sonraki görünür aktivitelerine gidilir. Zaman sırası tek başına talimatın
  uygulandığının veya aktiviteye neden olduğunun kanıtı sayılmaz.
- Talimatın uygulandığına dair özel bir değerlendirme sunulursa kaynak kanıt ve değerlendirme yöntemi gösterilir;
  genel durumda “Application not confirmed” kalabilir. LLM'in “tamam” demesi yürütme kanıtı değildir.
- Timeout/unknown durumunda mevcut yeniden gönderimsiz recheck ve idempotence korunur.
  Poll sırasında taslak, seçili ajan ve focus kaybolmaz.

Kabul ölçütleri:

- [ ] Kabul edilmiş ama bağlama eklenmeden biten çalışma ile bağlama eklenmiş mesaj ayrı gösterilir.
- [ ] “In agent context” mesajına bağlı sonraki aktiviteler filtrelenebilir; otomatik başarı iddiası yoktur.
- [ ] Mesaj gönderme/iptal/restart/timeout regresyonları ve şifreleme/maskeleme testleri geçer.
- [ ] Motor sürümü veya native yetenek desteklemiyorsa neden disabled olduğu açıkça gösterilir.

## SKY-05 — Canlı tarayıcı görünümü

**Amaç:** Operatörün seçtiği ajanın gözlemlenebilir tarayıcı faaliyetini gerçek kaynaktan izlemesi.

Beklenen davranış:

- Önce kurulu Strix'in gerçek stream/screenshot/artifact yetenekleri kaynak kodu ve çalıştırma ile doğrulanır.
  Veri yoksa unavailable gösterilir; demo akış veya ayrı bir tarayıcıyı ajanın ekranı gibi sunma.
- Ajan seçildiğinde o ajana ait olduğu doğrulanmış görüntü gösterilir. Tarama, ajan, kaynak,
  çekim zamanı ve son alınma zamanı görünür; ajan değişince eski görüntü yeni ajanınmış gibi kalmaz.
- Gerçek stream varsa “Live”; periyodik fotoğrafta “Latest screenshot”; eski kaynakta “Stale”,
  bitmiş çalışmada “Recorded”. UI'da açıkça tanımlanmış tazelik eşiği kullanılır.
- İzleme salt okunurdur. Tarayıcıyı uzaktan kontrol etme bu talebin kapsamı değildir.
- Görüntüler kimlik bilgisi/kişisel veri içerebilir: sadece metin log redactor'ının yeterli olduğunu varsayma.
  Koruma ve erişim politikası uygulanamayan görüntü yayımlanmaz; tokenlı kaynak URL'leri sızdırılmaz.

Kabul ölçütleri:

- [ ] Destek yok, görüntü eskidi, bağlantı koptu ve ajan değişti durumları dürüstçe gösterilir.
- [ ] Ekran görüntüsü yenilenmesi yeni hedeflere gezinme veya yeni pentest isteği üretmez.
- [ ] Görsel sır sızıntısı ve yanlış ajana ait kaynak eşleştirmesi test edilir.

## SKY-06 — Olay zaman çizelgesi ve sonradan oynatma

**Amaç:** “Tarama sırasında hangi sırayla ne oldu?” sorusuna canlı ve geçmiş çalışmalar için cevap vermek.

Beklenen davranış:

- Ajan oluşumu/durumları, araç çağrı/sonuçları, oturum olayları, operatör talimatı durumları ve bulgu
  gözlemleri ortak zaman çizelgesinde filtrelenir. Her olay kaynağına/kanıtına açılır.
- Canlı takip ile geçmiş inceleme ayrılır. Geçmişte zaman imleci, ileri/geri ve oynatma hızı olabilir.
  Görünüm o ana kadar kaydedilen olayları gösterir; sonradan öğrenilen bilgiyi geçmişte biliniyormuş gibi sunmaz.
- Kaynak zamanı bilinmiyorsa “Timestamp unavailable”; yalnız alım zamanı varsa bu açıkça belirtilir.
  Farklı kaynaklar arasında kesin sıralama veya nedensellik kanıtı uydurulmaz.
- Stabil olay kimlikleri ve artımlı sayfalama kullanılır; poll/import/resume olayları çoğaltmaz.
  UI kart sınırının dışında kalan kayıtlara geçmişten ulaşılabilir; veri yoksa sonradan üretilmez.

Kabul ölçütleri:

- [ ] Replay hiçbir HTTP test isteğini, araç çağrısını, ajan talimatını veya taramayı yeniden çalıştırmaz.
- [ ] Eksik zamanlı/sıra dışı gelen olaylar, aynı zamanlı olaylar ve tekrar ingest test edilir.
- [ ] Büyük geçmişte filtre ve sayfalama kullanılabilir; sırlar maskeli kalır.

## SKY-07 — Bulgu kanıt çalışma alanı

**Amaç:** Analistin bulguyu orijinal kanıtı kaybetmeden incelemesi ve değerlendirmesini kaydetmesi.

Beklenen davranış:

- Bulgu occurrence'ı ve seçili doğrulama çalışması bağlamında saldırı ve kontrol istekleri yan yana.
  Maskeli request/response başlıkları ve gövdeleri, anlaşılır fark görünümü, mevcutsa bağlı ekran görüntüleri.
- Kullanıcı hangi kaydın saldırı, hangisinin kontrol olduğunu ve hangi tarama/ajana ait olduğunu görür.
  Otomatik eşleştirme yalnız aday ise aday olarak etiketlenir; rastgele iki kayıt kontrol çifti yapılmaz.
- Analist yorum/açıklama ekleyebilir. Yazar ve zaman tutulur; düzenlenen notun geçmişi korunur.
  Notlar orijinal request/response, bulgu metni veya Verify kanıtını değiştirmez.
- Ham orijinal artefaktlar korunur; görüntüleme/indirme mevcut maskeleme ve erişim politikasına uyar.
  Diff maskelenmiş içerikten üretilir; maskeleme nedeniyle farkların görünmeyebileceği belirtilir.
- Eksik, kırpılmış veya silinmiş kaynak açıkça gösterilir. Analist yorumu makine kanıtı veya otomatik
  remediation/doğrulama sonucu olarak kullanılmaz.

Kabul ölçütleri:

- [ ] Yorum ekleme/düzenleme orijinal kanıtı ve geçmiş doğrulama sonucunu değiştirmez.
- [ ] Hem iki panelde hem diff/not/indirme yollarında sırlar korunur; HTML/script içeriği güvenli gösterilir.
- [ ] Saldırı/kontrol bağlantıları ve tarama/occurrence ayrımı test edilir; yeni doğrulama eski kanıtı ezmez.
- [ ] Eksik kanıt ve tekrar içe aktarma kayıp veya çoğalma üretmez.

## Uygulama sırası ve tamamlanma kaydı

Kullanıcının sabitlediği bir öncelik sırası yoktur. Bağımlılıklara göre öneri:
mevcut kaynak/kanıt kimliklerini incele → SKY-07 ve SKY-02 → SKY-03 → SKY-01;
mevcut mesajlaşma üstünde SKY-04 → ortak kaynaklardan SKY-06.
SKY-05 native yetenek araştırması sonrasında desteklendiği ölçüde uygulanır.
Ortak altyapıyı yalnız bu kabul ölçütlerinin gerektirdiği kadar genişlet; ayrı bir Strix orkestrasyonu kurma.

Her özellik için PROGRESS kaydında şunlar bulunmalı:

1. Değişen kullanıcı davranışı ve mevcut işlevlerden yeniden kullanılanlar.
2. Gerçek kaynak/kanıt yolu ve uygulanmayan veya desteklenmeyen kısımlar.
3. Anlamlı testler, sonuçları ve gerçek çalışma kabul kanıtı varsa ayrı açıklaması.
4. İki viewport ekran görüntüleri, inceleme sonucu ve düzeltilen kusurlar.
5. Kabul ölçütlerinden kalanlar. Sadece UI çizmek veya endpoint eklemek “tamamlandı” sayılmaz.
