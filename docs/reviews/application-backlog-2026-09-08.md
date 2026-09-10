# Security Audit Kit — değerlendirme iş listesi

Kaynak: [8 Eylül 2026 çok rollü değerlendirme](application-review-2026-09-08.md). Yerel baz: `48fad91`.

**Güncelleme — 10 Eylül 2026:** 8 Eylül değerlendirmesinin ardından 3 yeni F kartı (F23–F25) ve 1 koşullu R kartı (R11) eklendi. F22 tamamlandı; kalan 24 F kartı ve 11 R kartı aşağıda yer alıyor. F23–F25 mevcut kartların boşluklarını kapatır: Python modül testleri (F09'un ön koşulu), config doğrulama (F11'in uygulama uzantısı) ve tüketici geçiş rehberi (F08'in tamamlayıcısı). R11 araç pin güncelleme otomasyonudur ve koşullu bırakılmıştır. F12 ölçüm notu eklendi: kalibrasyon skorlayıcısı implementasyonu, Qwen 3.7 Max + GLM-5.1 ilk ölçüm sonuçları ve karar kaydı. [Roadmap eşleme ve karar gerekçeleri](roadmap-reconciliation-2026-09-08.md).

P0: sonuç/kayıt güvenini doğrudan bozan doğrulanmış hata. P1: sonraki güvenilirlik ve kullanılabilirlik paketi. P2: ölçüm ve talebe göre geliştirme. P0 etiketi CVSS veya istismar şiddeti değildir. Efor: K ≈ 0,5–2, O ≈ 3–5, B ≈ 6–10 mühendis-gün; test ve doküman dahil kaba tahmin, takvim sözü değil.

## Öncelik tablosu

| ID | İş | Tür / kanıt | Öncelik | Rol | Efor | Bağımlılık |
|---|---|---|---|---|---|---|
| F01 | Kilit alınamayan çalışmanın bütün çıktılarını ayır | Hata / D | P0 | Backend | O | — |
| F02 | Tarama sonucu ile engelleme politikasını ayır | Hata / D+K | P0 | Backend + güvenlik | O | — |
| F03 | Evidence/SARIF'i çalıştırma kimliğine bağla | Hata / D | P0 | Veri + backend | O | F01 |
| F04 | Eksik/hatalı kanıtı temiz göstermeyen rapor sözleşmesi | Hata / D+K | P0 | Raporlama + UX | K | F02, F03 |
| F05 | Kilit sahipliği ve uzun çalışma yarışlarını gider | Risk / K | P1 | Backend | O | F01 |
| F06 | Paket cache kararlarını politika değişiminde yenile | Risk / K | P1 | Güvenlik | O | — |
| F07 | Stabil release'te doğrulanamayan CI'ı durdur | Risk / K | P1 | Release | K | — |
| F08 | Stabil/RC güncelleme kanallarını ayır | Risk / K | P1 | Release | K | — |
| F09 | Deterministik e2e'yi PR kapısı yap | Kalite / K | P1 | QA + CI | O | —; P0 testleri eklenecek |
| F10 | Mevcut hook'ları koruyan kurulum ve geri alma | UX / K | P1 | DX | O | — |
| F11 | Kitin kendi güven sınırlarını ve hardening seçeneklerini çıkar | Risk / K | P1 | Güvenlik | O | — |
| F12 | Kalibrasyon hazırlığı → ölçüm → karar sözleşmesi | Araştırma / K | P1 | AI + güvenlik | B | a: yok; b: erişilebilir backend; c: ölçüm |
| F13 | Yerel/ağsız/veri paylaşımı ifadelerini düzelt | Doküman / K | P1 | Ürün + güvenlik | K | — |
| F14 | Kapsam özeti, yardım ve kısa başlangıç akışı | UX / Ö | P1 | Ürün + DX | O | F02 |
| F15 | Landing dayanıklılık ve erişilebilirlik kontrolü | UX / K+Ö | P2 | Frontend + QA | K | — |
| F16 | Eksik boyutları normalize kanıt modeline ekle | Geliştirme / K | P1 | Veri | B | F02, F03 |
| F17 | Shell orkestrasyonunu kademeli modüllere ayır | Bakım / Ö | P2 | Mimari | B | F09, davranış sözleşmeleri |
| F18 | Platform ve boşluklu yol test matrisi | Kalite / K+Ö | P1 | QA + DX | O | F09 |
| F19 | Bulgu kimliği ve ortak karar kaydı | Geliştirme / K+Ö | P2 | Veri + güvenlik | B | F03, F16 |
| F20 | Yerel performans ve kapsam metrikleri | Geliştirme / Ö | P2 | Operasyon + ürün | O | F02, F03 |
| F21 | a: boyut cache; b: monorepo kapsamı | Geliştirme / Ö | P2 | Performans | B | a: F03, F05, F06, F20; b: a + ihtiyaç |
| F22 | Yol haritalarını tek güncel iş listesine bağla | Bakım / K | Tamamlandı | Ürün + bakım | K | 8 Eylül: bu belge + eşleme |
| F23 | Python modülleri için unit test altyapısı | Kalite / K | P1 | QA + backend | K | F09 ile birlikte |
| F24 | Config dosyası doğrulama ve güvenli kaynaklama | Risk / K | P1 | Güvenlik + DX | K | F11 |
| F25 | Sürüm geçiş rehberi ve breaking change bildirimi | DX / Ö | P1 | Release + DX | K | F08 |

## Roadmap'ten gelen ek / koşullu kartlar

Bu tablo yukarıdaki F maddelerini tekrar etmez. “Koşullu” işler, belirtilen ihtiyaç ve bağımlılıklar doğrulanmadan uygulamaya alınmaz.

| ID | Eski referans / iş | Karar | Rol | Efor | Açılma koşulu / bağımlılık |
|---|---|---|---|---|---|
| R01 | T2.2 / #8 remediation compute | P1 kapsam kararı; uygulama koşullu | DX + güvenlik | K karar; O–B uygulama | Mevcut skill komutlarının yetmediği örnek |
| R02 | R5.3 skills-only plugin / manifest | P2 aday | DX + güvenlik | O | F10, F11, F14; daha kolay deneme ihtiyacı |
| R03 | A3 / #7 Python-JS reachability | Koşullu | Güvenlik + performans | B | F16, F21a; ölçülmüş yüksek triyaj yükü |
| R04 | L2 + Phase B provider/local runner | Koşullu | AI + mimari | B pilot; tam runner ayrıca tahmin | F12; gerçek offline/non-Claude gereksinimi |
| R05 | T3.4 generate-only PoC | Koşullu | Güvenlik + AI | B | F12c, F19; kanıt ihtiyacı |
| R06 | Python araçlarını hash-pin | Önce karar, ertelendi | Tedarik zinciri | K karar; O–B uygulama | F11; bakım/uyumluluk maliyeti kabulü |
| R07 | Tier S Layer 3 imzalı release | Ertelendi | Release + güvenlik | O | F07; yayıncı kimliği doğrulama talebi |
| R08 | A4/A5 statik situational scanner | Ertelendi | Güvenlik | Araç seçilince | Somut kapsam açığı; F16, pin/lisans incelemesi |
| R09 | CLI wizard | Son planlı özellik | DX + UX | O | Öncelikli aktif işler bittiğinde F14 verisiyle tasarım yenileme |
| R10 | T3.2 / B.1 skill extraction | Ertelendi | AI + bakım | O | R04 veya ölçülmüş bakım sorunu |
| R11 | Araç pin güncelleme otomasyonu | Koşullu | Tedarik zinciri + bakım | O | R06, F07; 3+ araç sürümü eskidiğinde veya CVE bildirildiğinde |

## İş kartları / kabul kriterleri

### F01 — Çalıştırma izolasyonu

Kilit bekleme süresi dolan tarama, diğer taramanın summary/SARIF/evidence/HTML dosyalarını değiştirmemeli. Her çalıştırma benzersiz dizin ve kimlik almalı; son tamamlanan çalışma işaretçisinin güncellenmesi açık bir sahiplik kuralına bağlı olmalı. İki eşzamanlı tarama ve kilit zaman aşımı testi tüm artifact'ların kendi çalışmasına ait kaldığını doğrulamalı. İptal edilmiş çalışma son başarılı kaydı bozmamalı.

### F02 — Durum ve politika

Boyut sonucu en az `pass`, `findings`, `error`, `skipped`, `indeterminate`, `not_applicable` ayrımını ve nedenini taşımalı; adlandırma schema tasarımında kesinleşebilir. `gate` sonucu ayrı hesaplanmalı. Eksik Docker/uvx, eksik manifest, araç çökmesi ve soft-fail bulgusu için fixture olmalı. Mevcut tüketicilere schema geçişi belgelenmeli. Varsayılan fail-open kararını değiştirmeden yanlış `pass` giderilebilmeli.

### F03 — Artifact kökeni ve güncellik

Evidence yalnız aynı run manifestindeki çıktıları tüketmeli. Önceki SARIF + bu çalışmada atlanan/başarısız boyut, güncel bulgu olarak alınmamalı. Commit, dirty durumu, kapsam, araç/config/rule kimliği ve üretim zamanı için alanlar tanımlanmalı. Aynı içerikten deterministik bulgu üretimi korunmalı; çalıştırma metadata'sı ayrı tutulmalı. Eksik/bozuk çıktı görünür uyarı veya hata üretmeli.

### F04 — Dürüst rapor

Çıkış kodu yoksa veya kapsam eksikse HTML `clean` dememeli. Araç hatası bulgu gibi sunulmamalı; sıfır gate kodu “bütün boyutlar temiz” anlamına gelmemeli. Tarama tarihi ile rapor üretim tarihi ayrılmalı. Açıkça çağrılan `report`/`evidence` üretilemediyse makine tarafından anlaşılabilir başarısızlık dönmeli; isteğe bağlı tarama sonrası rapor hatasının gate'e etkisi ayrıca belgelenmeli. Null/missing/3/1/0 durumları test edilmeli.

### F05 — Kilit yaşam döngüsü

Canlı ve uzun süren taramanın kilidi yalnız yaşı nedeniyle alınmamalı. Release yalnız kendi token'ını taşıyan kilidi kaldırmalı. Ölü PID, PID yeniden kullanımı, heartbeat yokluğu, aynı anda stale reclaim ve INT/TERM testleri yapılmalı. Bozuk kilit dosyası sonsuz beklemeye yol açmamalı.

### F06 — Politika farkındalığı olan paket cache'i

Aynı paket/sürüm için önce izin veren, sonra `BLOCK_EXTRA` ile engelleyen politika doğru uygulanmalı. Cache anahtarı veya yeniden sınıflandırma policy/rule sürümünü kapsamalı. Eksik/yarım cache ve eşzamanlı yazma atomik olarak yönetilmeli. Tam sürüm ve sürümsüz istekler için yenileme kuralı ve `refresh` yolu belgelenmeli; INDETERMINATE kalıcı temiz karara dönüşmemeli.

### F07 — Release kapısı

Eksik gh, başarısız API, boş/eksik/pending check-run ve doğrulanamayan remote HEAD stabil release'i durdurmalı. Aynı SHA için eski başarısız/yeni başarılı rerun seçimi deterministik olmalı. Ağ ve gh fixture'larıyla test edilmeli; testler etiket veya release yayımlamamalı. İstisna yolu kabul edilirse gerekçe kaydı zorunluluğu tasarımda açık olmalı.

### F08 — Güncelleme kanalı

`v1.17.0`, `v1.18.0-rc.1`, `v1.18.0` içeren yerel tag fixture'ında varsayılan öneri son stabil olmalı. RC yalnız açık kanal seçimiyle önerilmeli. Erişim hatası, güncelleme var ve güncel sonuçları ayırt edilmeli. Ağsız fixture testleri yeterli; test için release açılmamalı.

### F09 — Test otomasyonu

PR'da dış API anahtarı gerektirmeyen e2e işi çalışmalı ve zorunlu check listesine eklenmeli. E2e için açık offline modu bulunmalı; test sonucu pass/fail/skip sayılarını yayınlamalı. F01–F06 fixture'ları regresyon kapsamına girmeli. Gerçek tarayıcı smoke testleri ayrı işte sürüm/adaptör uyumunu sınamalı; toolchain eksikliği orada başarılı test sayılmamalı.

### F10 — Kurulum / geri alma

Varsayılan, özel hooksPath ve pre-commit framework fixture'ları hazırlanmalı. Mevcut entegrasyon sessizce devre dışı bırakılmamalı; `--skills-only` dahil somut kurulum planı gösterilmeli. Kitin yaptığı değişiklikleri kaydeden idempotent rollback/uninstall yolu mevcut config ve kullanıcı hook'larını korumalı. Yeni kurulum gereksiz ek etkileşim istememeli; karar yalnız gerçek çakışmada gerekli olmalı.

### F11 — Kit tehdit modeli

Config, taranan kod, scanner çıktısı, AI talimatı, cache, vendor ve dış registry için veri/yetki akışı çıkarılmalı. Config'in çalıştırılabilir olduğu açıkça yazılmalı. Salt okunur kaynak + ayrı yazılabilir artifact mount'u en az gitleaks ve trivy fixture'ıyla sınanmalı. Uyumluluk kırılıyorsa geçiş maliyeti kaydedilmeli; doğrulanmamış risk exploit diye sunulmamalı.

### F12 — AI karar kalitesi

**F12a — Anahtarsız hazırlık (L1d i/ii):** Mevcut prompt/skill/rubric farkı ve confidence'ın P(REAL) mi yoksa karara güven mi olduğu belgelenmeli. Geçmiş prompt/sonuçlar korunarak dev-only aday sözleşme hazırlanmalı; 31 dev + 36 holdout sayısı otomatik raporlanmalı. Grader sentetik girdilerle threshold-cost, abstention ve provider hatalarını ayırmalı. Brier ancak değişken anlamı netken; ECE yeterli dağılım varsa raporlanmalı. API anahtarı yokluğu bu hazırlığı engellemez.

**F12b — Ölçüm (L1d iii/iv):** Aynı split ve veri sürümünde mevcut/adayı karşılaştır; prompt hash'i/model/run kimliği kaydedilsin. GLM gibi erişilebilir backend erken sinyal sağlayabilir; ürünün varsayılan backend'inden ölçüm olmadan shipped skill veya eşik değişikliği çıkarılmamalı. Provider hataları karar kalitesine karıştırılmamalı. Farklı split/sürümler tek skor altında toplanmamalı. Bu planlama turu ücretli koşum başlatmaz.

**F12c — Ürün sözleşmesi:** F12b sonrasında eksik bağlamı UNCERTAIN olarak kaydeden ve otomatik FP allowlist'ine sokmayan aday doğrulansın. Skill ve grader aynı karar kümesini kullansın; REAL recall, precision, abstention ve değerlendirilen vaka oranı birlikte izlensin. Yeni dev vakalarıyla geliştirme ardından dondurulmuş prompt yeni kör vakalarla doğrulansın. **0.7 eşik değişikliği mevcut verilere dayanarak planlanmadı.** Deep/AI-review ve çıktıya gömülmüş talimat enjeksiyonu ayrı alt eval kapsamlarıdır.

**F12 ölçüm notu — 10 Eylül 2026:** Kalibrasyon skorlayıcısı `score.mjs`'e eklendi (Brier, ECE, reliability tablosu, 0.7 eşik maliyeti). `grade.mjs`'e dokunulmadı; geçmiş run'lar karşılaştırılabilir. İlk ölçümler iki backend üzerinde tamamlandı:

| Split | Backend | n | Precision | Recall | F1 | Brier | ECE | suppressed REAL | noise FP |
|---|---|---|---|---|---|---|---|---|---|
| dev | Qwen 3.7 Max | 31 | 100.0% | 93.3% | 96.6% | 0.4374 | 0.4484 | 0 | 0 |
| dev | GLM-5.1 | 31 | 100.0% | 93.3% | 96.6% | 0.4305 | 0.4355 | 0 | 0 |
| holdout | Qwen 3.7 Max | 32/36* | 100.0% | 100.0% | 100.0% | 0.3399 | 0.3422 | 0 | 0 |
| holdout | GLM-5.1 | 36 | 94.7% | 100.0% | 97.3% | 0.3832 | 0.3853 | 0 | 1 |

*Qwen holdout'ta 4 vaka provider quota hatası (429) nedeniyle skorlanamadı; `EVAL_ALLOW_PARTIAL=1` ile kalan 32 vaka skorlandı.

**Bulgu 1 — Karar doğruluğu yüksek, kalibrasyon kötü.** Her iki model ~%97 accuracy ve %93+ recall üretiyor; aynı vakaları kaçırıp aynı vakaları yakalıyorlar. Bu, prompt'un belirleyici faktör olduğunu, model seçiminin karar sınırını değiştirmediğini gösteriyor. Ancak her iki model de ~%96 ortalama confidence veriyor ve gerçek REAL oranı ~%50 — ECE 0.34-0.45 aralığı (iyi kalibrasyon <0.05 olmalı). Confidence ayırt edici güç taşımıyor: doğru ve yanlış cevaplara aynı güven veriliyor.

**Bulgu 2 — 0.7 eşiği şu an etkisiz.** Her iki modelde suppressed REAL = 0 (eşik kimseyi bastırmıyor) ve noise FP ≈ 0 (eşik üstünden sızan FP yok). Modeller FP'leri zaten FP olarak doğru tanıyor; eşik fonksiyonel olarak gereksiz ama zararlı da değil. Eşik değişikliği (F12c) şu an acil değil.

**Bulgu 3 — confidence tanımı belirsiz.** `triage_prompt.md` "assign a confidence in [0,1] that this is a real, exploitable issue" diyor. Modeller bunu "kararıma güven" olarak yorumluyor, P(REAL) olarak değil. Prompt'un belirsizliği kalibrasyon hatasının kök nedeni — model hatası değil. F12a kapsamında bu tanım netleştirilmeli.

**Bulgu 4 — NVIDIA NIM GLM-5.2 end-of-life.** `z-ai/glm-5.2` modeli Ağustos 2026'da EOL olmuş (410 Gone). GLM ölçümleri DashScope Standard üzerinden `glm-5.1` ile yapıldı. `promptfooconfig.nim.yaml` artık çalışmıyor; `promptfooconfig.glm-ds.yaml` yeni GLM config'idir.

**Karar:** Kalibrasyon düzeltmesi **acil değil**. Ürün şu an karar doğruluğuyla çalışıyor; confidence'ın ayırt edici gücü ancak confidence'a dayalı bir ürün özelliği çıktığında (önceliklendirme, JSONL event store, incremental triage) problem olur. F12a'da confidence tanımı belgelenmeli, F12c'de prompt revizyonu ile çözülmeli. Hedef: revize sonrası holdout ECE < 0.15.

**Altyapı notu:** `run.sh` write-to-temp-then-move pattern'ına geçirildi — başarısız run artık önceki artefaktı yok etmiyor. `score.mjs` thinking/reasoning prefix'li çıktıları (Qwen, GLM chain-of-thought) `extractJsonBlock()` ile doğru parse ediyor. `promptfooconfig.qwen.yaml` (Qwen 3.7 Max) ve `promptfooconfig.glm-ds.yaml` (GLM-5.1) yeni backend config'leridir.

### F13 — Veri akışı açıklaması

Her komut için yerel hesap, internet ihtiyacı ve dış servise gönderilebilecek veri türleri listelenmeli. Landing meta/karşılaştırma, README'ler ve HTML footer aynı sınırlamaları taşımalı. “Nothing leaves” gibi mutlak iddia yalnız onu gerçekten sağlayan bileşende kullanılmalı. Gerçek trafik ölçümü yapılmazsa tablo bunun kod/araç sözleşmesi incelemesine dayandığını söylemeli.

### F14 — İlk kullanım ve kapsam

Yeni kullanıcı kısa başlangıç üzerinden `doctor → scan → sonucu anla → next step` akışını tamamlayabilmeli. Yardımda her komutun boyutları, önkoşulları ve gate davranışı görünmeli. `all` dışında kalan boyutlar kapsam özetinde açık olmalı. Profiller eklenecekse mevcut varsayılanlar korunmalı. En az birkaç gerçek kullanıcıyla ilk rapora ulaşma süresi ve yanlış kapsam yorumları ölçülmeli; hedefler baz ölçüm sonrası kesinleşmeli.

### F15 — Landing kalite turu

Dar/geniş ekran, klavye, ekran okuyucu temel akışı, JS kapalı kullanım ve clipboard reddi tarayıcıda doğrulanmalı. Kritik içerik JS hatasında görünür kalmalı; kopyalama sonucu ve hatası erişilebilir bildirim vermeli. Mevcut reduced-motion desteği korunmalı. Bulunmayan sorunlar için sırf checklist tamamlamak amacıyla tasarım değiştirilmemeli.

### F16 — Tam kanıt kapsamı

**F16a doğrulama:** Komut → native çıktı → evidence → HTML/SARIF matrisi yayımlanmalı. Eski plan #12'de açık kalan trivy/uv.lock üçüncü suppression yolu, ilgili advisory/paket fixture'ıyla doğrulanmalı; aynı CVE her araçta varmış gibi varsayılmamalı. **F16b adaptörler:** pip-audit, JS audit, checkov, GuardDog adaptörleri ayrı küçük işler olarak uygulanmalı. Her adaptör temiz/bulgulu/hatalı native fixture ile test edilmeli. Çıkışı olmayan boyut için “0 bulgu” yerine kanıt eksikliği gösterilmeli. Şiddet kaynağı korunmalı ve CVSS uydurulmamalı.

### F17 — Modüler bakım

Önce durum/çıkış kodu/çıktı sözleşmesi sabitlenmeli. Adaptörler, discovery ve artifact yönetimi ayrı modüllere küçük PR'larla çıkarılmalı; CLI uyumluluğu korunmalı. Bash 3.2 hedefi varsa her adım buna göre sınanmalı. Modülerleşme yeni runtime bağımlılığı doğuracaksa faydası ayrıca ölçülmeli.

### F18 — Platform ve yollar

Linux ve macOS otomatik smoke testleri; WSL2 için gerçekten çalıştırılmış sonuç veya açık “doğrulanmadı” durumu bulunmalı. Minimum Python sürümü belgelenmeli. Boşluk/Türkçe karakter içeren repo ve dosya yolları, worktree, unborn/shallow repo ile deleted/renamed dosyalar test edilmeli. Boşlukla bölünen argümanlar dizi/NUL güvenli işleme geçirilmeli.

### F19 — Bulgu / karar yaşam döngüsü

Satır kayması aynı bulguyu gereksiz yeniden açmamalı; aynı manifestte aynı CVE'li iki farklı paket kaybolmamalı. Paket kimliği ve araç fingerprint'i için fixture hazırlanmalı. Karar kaydı owner/gerekçe/son tarih/doğrulama koşullarını taşımalı. Alias eşleme kaynağı ve uygulanabilir tarayıcılar belirtilmeli; belirsiz eşleşme otomatik suppression üretmemeli. Geriye uyum/migrasyon tasarımı yapılmalı. T3.1'den kalan JSONL olay geçmişi ve Phase A SQLite/checkpoint fikri bu modelin koşullu devamıdır: kesilen uzun AI koşumlarında tekrar maliyeti ölçülmeden iki ayrı kalıcı depolama sistemi eklenmemeli; ihtiyaç varsa tek formatla başla, crash/resume ve idempotent replay sınansın.

### F20 — Önce ölçüm

Boyut bazında süre, durum nedeni, kapsam ve cache hit bilgisi yerelde üretilmeli. Küçük repo, monorepo ve büyük geçmiş fixture'larında sıcak/soğuk koşum ayrılmalı. Gizli veri veya kaynak kod metriklere girmemeli; ağ telemetrisi varsayılan olarak eklenmemeli. F21 için ölçülmüş darboğaz listesi çıkarılmalı.

### F21 — Cache / monorepo

**F21a = R5.2 slice B:** Yalnız boyut cache'i teslim edilir. **F21b = R5.4:** F21a'nın doğrulanmış input-hashing altyapısını kullanır; gerçek monorepo darboğazı varsa ayrı teslim edilir. F21b, F21a'nın çıkışını bekletmez. Kod/lockfile/config/rules/tool/advisory güncelliği değişince doğru invalidation gösterilmeli. Cache açık ve kapalı koşumlar aynı kapsamda aynı sonucu üretmeli. Monorepo ortak lockfile ve paylaşılan bileşen değişiklikleri alt ağaç taramasından kaçmamalı. Kazanç F20 bazına göre raporlanmalı; doğruluk sağlanmadan hız başarısı kabul edilmemeli.

### F22 — Tek planlama kaynağı

**Tamamlandı — 8 Eylül 2026:** F ve R kimlikleriyle tek güncel sıra oluşturuldu, eski roadmap/planlara yönlendirme eklendi, tamamlanan işler ve koşullu kalanlar eşleme belgesine işlendi. Tarihsel notlar korunuyor. R5.2 slice A yerel main'de ve yerel CHANGELOG'da Unreleased olarak kayıtlı; remote release durumu doğrulanmadı. GitHub issue/PR oluşturulmadı. Gerçek geliştirmeye geçerken kişi/tarih ve uzak yayın durumu ayrıca güncellenir.

### F23 — Python modülleri için unit test altyapısı

`lib/` altındaki dört Python modülü (`evidence.py`, `kit_sarif.py`, `pkgcheck.py`, `report_html.py`) yalnız e2e testlerle dolaylı olarak sınanıyor. Severity normalization, SARIF ayrıştırma, HTML escape ve pkgcheck sınıflandırma mantığı için doğrudan unit testleri bulunmuyor.

**Kabul kriterleri:**
- `lib/` modülleri için `tests/unit/` dizininde pytest tabanlı test altyapısı kurulmalı; dış bağımlılık eklenmemeli (yalnız stdlib + pytest).
- CI'a `pytest` adımı eklenmeli; F09 PR kapısının zorunlu kontrollerinden biri olmalı.
- Her modül için en az şu senaryolar sınanmalı: `evidence.py` — severity normalization tablosu (CVSS bantları, SARIF level, tool default), dedup mantığı, eksik/bozuk SARIF davranışı; `report_html.py` — HTML escape, eksik `exit_code` durumu (F04 ile bağlantılı), sıfır bulgu çıktısı; `kit_sarif.py` — boş finding listesi (yazılmamalı), suppression rendering; `pkgcheck.py` — install komut ayrıştırma, block/report sınıflandırma.
- Fixture verileri `tests/fixtures/` altında, sentetik SARIF/JSON dosyaları olarak tutulmalı; gerçek tarama çıktısı kullanılmamalı.
- Testler `PATH=/usr/bin:/bin:/usr/sbin:/sbin` ile (dış araçlar olmadan) çalışabilmeli.
- F09 ile aynı PR'da veya hemen ardından teslim edilmeli; F01–F04 düzeltmeleri geldiğinde her biri ilgili unit testle birlikte olmalı.

### F24 — Config dosyası doğrulama ve güvenli kaynaklama

`.security-audit.conf` dosyası `scan.sh` içinde `source` ile yükleniyor (`scan.sh:48`). Bu, dosyanın çalıştırılabilir bash kodu olduğu anlamına gelir — F11'de belirtilen tehdit modelinin bir parçası. Mevcut durumda syntax hatası, geçersiz değişken ataması veya beklenmeyen komut satırı kullanıcıya anlamlı bir hata üretmiyor; sessizce yanlış değerlerle tarama devam edebiliyor.

**Kabul kriterleri:**
- `scan.sh doctor` komutu aktif config'i çözümlemeli; tanınmayan değişken, syntax hatası ve tehlikeli komut (`rm`, `curl`, `eval` gibi) içeriyorsa uyarı vermeli.
- Config'deki her değişken bilinen değişken listesiyle (`security-audit.conf.example`'dan üretilmiş) karşılaştırılmalı; bilinmeyen değişken `WARN` olarak raporlanmalı.
- `scan.sh verify` kapsamına config dosyası eklenmeli — örnek dosyadan yapısal sapma (eksik zorunlu alan, tip uyumsuzluğu) tespit edilmeli.
- Config doğrulama başarısızlığı taramayı engellememeli (fail-open korunur); ancak uyarı banner'ı yazdırılmalı ve `summary.json`'a kaydedilmeli.
- `security-audit.conf.example` dosyası her yeni config değişkeninde güncellenmeli; CI'da örnek ve gerçek config şemasının uyumu kontrol edilmeli (F09 test kapısına eklenecek assertion).
- F11 ile birlikte veya hemen ardından teslim edilmeli; F11 tehdit modeli config'in çalıştırılabilir doğasını belgelediğinde, F24 bu belgeye referans veren somut kontrolü sağlar.

### F25 — Sürüm geçiş rehberi ve breaking change bildirimi

Tüketiciler `bootstrap.sh` ile sürüm güncelliyor ancak sürümler arası breaking change'ler (evidence schema değişikliği, kaldırılan komut, değişen config değişkeni, yeni zorunlu araç) yalnız CHANGELOG'da yazılı. `bootstrap.sh --check` yeni sürüm olduğunu bildiriyor ancak neyin değiştiğini veya tüketicinin ne yapması gerektiğini söylemiyor. F08 kanal ayrımı tamamlandığında RC/stabil ayrımı netleşecek; ancak stabil sürümler arası geçişte de rehber eksik.

**Kabul kriterleri:**
- Her release PR'ında CHANGELOG'a ek olarak `MIGRATION.md` veya CHANGELOG içine gömülü **upgrade notes** bölümü hazırlanmalı. Bu bölüm yalnız breaking change'leri ve gerekli tüketici eylemlerini listelemeli.
- `bootstrap.sh --check` çıktısı, mevcut `.kit-version` ile hedef sürüm arasındaki breaking change'leri özet olarak göstermeli (CHANGELOG'dan otomatik çıkarılabilir veya elle hazırlanmış bir `UPGRADE-NOTES` dosyasından okunabilir).
- Evidence schema sürümü (`security-audit-kit/evidence@1`) değiştiğinde eski `evidence.json` dosyasının ne olacağı belgelenmeli; migrasyon script'i gerekiyorsa aynı PR'da teslim edilmeli.
- Kaldırılan veya yeniden adlandırılan `scan.sh` komutları için en az bir sürüm boyunca deprecation uyarısı verilmeli; komut kaldırıldığında eski ad çağrıldığında yeni karşılığına yönlendirme yapılmalı.
- `install.sh` tekrar çalıştırıldığında config dosyasının üzerine yazmadan önceki ve sonraki sürüm farkını göstermeli (F10 ile örtüşür).
- F08 ile aynı teslimat diliminde (sıra 4) veya hemen ardından teslim edilmeli; ilk stabil yayın öncesi hazır olmalı.

### R01 — Remediation compute kapsam kararı

Önce bir doğrudan, bir transitif ve bir parent-range engelli örnek üzerinden mevcut skill'in read-only komutlarıyla öneri üretilebildiğini değerlendir. Yeterliyse görev komut/prosedür netleştirmesiyle kapanır; resolver ürünü yazılmaz. Yetmiyorsa tek ekosistemle başlayacak helper tasarımı çıkar; manifest/range/fix sürümü kaynağı kanıt olarak gösterilsin. Paket kurma, build script çalıştırma veya kör force-pin otomatik adım olmasın. Diğer ekosistemlere genişleme ayrı tahminlenir. Karar F16'dan bağımsız; normalize bulguya bağlanan helper F16'ya bağlı.

### R02 — Skills-only deneme kanalı

Önce vendored scanner bulunan/bulunmayan repo ve farklı çalışma dizini sözleşmesi yazılsın. Plugin kiti otomatik indirmesin, hook/config'i sessiz değiştirmesin; eksik tarayıcı için temiz önkoşul açıklaması üretsin. Manifest, sürüm, kök çözümleme ve izin bildirimi hedef host üzerinde test edilsin; `allowed-tools` tek başına sandbox garantisi diye sunulmasın. Deterministik tarayıcı vendored+pinned kalsın. Claude kanalının açılması tam Phase B gerektirmez; başka host desteği ayrıca talep ve test ister.

### R03 — Ağır reachability pilotu

Go call-analysis yeniden yazılmayacak. Python veya JS'de somut triyaj maliyeti varsa tek stack'te pilot yap; kurulum/süre ve doğrulanmış faydayı ölç. İşaretli “çağrılmadı” bulguları gate'ten otomatik düşürme. Build script yürütme gereksinimi, offline sınırları ve çıktı kapsamı açıkça belgelensin. Pilot F21a cache doğruluğu ve F16 adaptör sözleşmesini kullansın; fayda yoksa entegrasyon kapanır.

### R04 — Provider bağımsızlığı / yerel triage

İki ayrı ürün kurulmasın: önce mevcut harness'te ihtiyaç duyulan adayın triage kalitesini ölç, yalnız kabul edilen aday için küçük opt-in runner tasarla. Belirsiz sonuç güçlü backend'e yükseltilsin; gerçek air-gap'te yükseltme mümkün değilse UNCERTAIN olarak kalsın. Tam agent loop/MCP/tool policy işi yalnız triage pilotu ihtiyacı karşılamazsa açılır ve ayrıca tahminlenir. Deep inceleme ölçülmemiş yerel modele aktarılmaz; model boyutu tek başına kalite kanıtı değildir. R10 extraction ihtiyaç doğarsa bu programın parçası olur.

### R05 — PoC üretimi

Yalnız açık seçilmiş bulgu için precondition, sentetik veri ve insanın inceleyeceği repro artifact'ı üret. Otomatik çalıştırma, canlı hedefe istek veya “üretildi = doğrulandı” kararı olmasın. Üretilen ve insan tarafından doğrulanan kanıt ayrı durum taşısın. Kalite ölçümü ve F19 kimliğiyle ilişki olmadan genel PoC motoru açılmasın.

### R06 — Python hash-pin kararı

F11'de belirlenen bütünlük ihtiyacına karşı platform/araç bağımlılık kilitlerinin güncelleme maliyetini çıkar. Mevcut on-demand kullanım ile hash doğrulanan küçük bir araç pilotunu kıyasla. Karar kabul edilirse refresh, hash uyuşmazlığı, platform desteği ve offline cache testleri birlikte tasarlanır; bu kart doğrudan tüm araçları dönüştürme emri değildir.

### R07 — Yayıncı kimliği

Tüketicinin bağımsız imza doğrulama ihtiyacı varsa identity/issuer/version doğrulama politikası tasarla. İyi imza, yanlış yayıncı, yanlış artifact ve doğrulama hizmeti yokluğu test edilsin. Pin ve CHECKSUMS korunur. Anahtar/OIDC altyapısı kurmak veya yayın yapmak bu plan güncellemesinin parçası değil.

### R08 — Duruma özel statik kapsam

Scorecard/conftest/modelscan eski araştırma adaylarıdır, seçilmiş bağımlılık değildir. Somut tüketici ihtiyacı, mevcut araçların açığı, güncel lisans/pin, internet/token ve bakım maliyeti doğrulanmadan ekleme yapılmaz. Seçilen araç F02/F16 sözleşmesine uyar. Nuclei/DAST bu kartta kapsam dışıdır; eski “maybe” daha sonraki kapsam dışı kararıyla kapanmıştır.

### R09 — Wizard, en son

Önceki kullanıcı tercihi korunur: öncelikli aktif işler tamamlandıktan sonra mevcut mock o günkü komut/kapsam/rapor sözleşmesine göre yeniden değerlendirilir. Süresiz ertelenmiş fikirlerin hepsinin yapılmasını beklemek anlamına gelmez. Explicit `wizard` girişi, no-arg/headless uyumluluğu, EOF/back/NO_COLOR/ASCII/TR-EN, eksik araç açıklamaları sınanır. Yeni bağımlılık veya otomatik araç kurulumu yok; F14 temel UX düzeltmeleri wizard gerekçesiyle beklemez.

### R10 — Skill extraction

Sürekli token tasarrufu gerekçesiyle açılmaz. R04 tüketicisi veya ölçülmüş bakım sorunu varsa önce tablolar/prosedürler ayrılır; kanıt eşiği ve yargı kuralları yüklenemeyen opsiyonel referansa taşınmaz. Referans keşfi ve ürün davranışı host'ta test edilir; F12 kalite kapısı korunur.

### R11 — Araç pin güncelleme otomasyonu

Kit 7+ dış aracı pin'liyor (gitleaks, trivy, syft, osv-scanner, semgrep, checkov, pip-audit, guarddog, zizmor). Bu araçların sürüm/digest güncellemeleri tamamen manuel; Dependabot/Renovate entegrasyonu yok. Zamanla eski sürümler güvenlik açığı, uyumsuzluk veya performans kaybı riski oluşturur. `scan.sh`'in üstündeki `*_VER` / `*_DIGEST` değişkenleri tek güncelleme noktasıdır, ancak güncelleme sonrası `CHECKSUMS` yeniden üretimi, self-audit ve e2e koşumları manuel tetikleniyor.

**Kabul kriterleri:**
- Pin güncellemeleri için checklist veya GitHub Action hazırlanmalı: sürüm değişimi → `CHECKSUMS` yeniden üret → `scan.sh verify` → e2e → self-audit → PR.
- Dependabot/Renovate yerine kit'e özel hafif bir `scripts/check-pins.sh` yazılabilir; her aracın upstream release'ini sorgulayıp mevcut pin'le karşılaştırmalı (GitHub API, PyPI JSON, Docker Hub). Ağ erişimi gerektirdiğinden CI'da zamanlanmış iş (haftalık) olarak çalışmalı.
- Güncelleme PR'ı otomatik açılıyorsa template'de dogfood checklist (RELEASING.md'deki liste) zorunlu olmalı.
- Docker digest güncellemesi için `docker manifest inspect` veya eşdeğer bir yol kullanılmalı; etiket değişmeden digest değişimi (tag-repoint) mevcut guard ile yakalanmalı.
- Pin güncellemesi CHANGELOG'da `### Changed` altında izlenmeli; tüketicinin `bootstrap.sh` ile aldığı sürümde hangi araçların güncellendiği görünmeli.
- R06 (Python hash-pin) kararı sonrası Python araçları için de aynı mekanizma genişletilmeli.
- **Açılma koşulu:** 3+ araç sürümü upstream'den 2+ minor geride kaldığında veya pinli araçlardan birinde güvenlik bildirimi (CVE) yayınlandığında. F07 release kapısı ve R06 hash-pin kararı tamamlandıktan sonra önceliklendirilir.

## Güncel teslim sırası — ana planlama kaynağı

Aşağıdaki sıra tek ekip için önerilen varsayılandır; aynı satırdaki işler tek PR olmak zorunda değil. Koşullu işler açılmadığında sonraki bağımsız işi bekletmez. Önceki Paket A/B/C sırası bu tabloyla değiştirilmiştir.

| Sıra | Teslimat | Neden şimdi / bitiş kapısı |
|---|---|---|
| 0 | **F22 tamamlandı** | Tek sıra ve roadmap eşlemesi hazır |
| 1 | **F09 + F23** offline PR test kapısı ve Python unit test altyapısı | Yeni düzeltmeler tekrar kaybolmasın; F01–F06 regresyonları ilgili düzeltmeyle eklenir. F23 `lib/` modüllerinin doğrudan test edilmesini sağlar — F09'un zorunlu kontrollerinden biri |
| 2 | **F01 → F05** çalıştırma izolasyonu ve kilit sahipliği | Cache ve rapor öncesi ortak kayıt yarışlarını gider |
| 3 | **F02 → F03 → F04** durum, güncel kanıt, doğru rapor | Eksik/eskimiş tarama temiz görünmesin; F01 ve F02 schema tasarımı beraber yapılır. F23'teki unit test fixture'ları F02–F04 düzeltmeleriyle genişletilir |
| 4 | **F06 → F07 → F08 → F25** cache politikası, release, kanal ve geçiş rehberi | Bir sonraki stabil yayın için güvenilirlik kapısı; F07 zorunlu kontrollerine F09 dahil. F25 tüketicinin sürüm geçişinde ne yapacağını bilmesini sağlar |
| 5 | **F13 + F11 + F24** veri akışı, kit tehdit modeli ve config doğrulama | Yanlış yerellik iddiasını gider; F24 config'in çalıştırılabilir doğasını somut kontrol altına alır. R02/R06 için sınırları tanımla |
| 6 | **F18** platform/yol matrisi ve kalan WSL2 doğrulaması | Taşınabilirlik temel ürün vaadi; WSL2 ortamı yoksa diğer testler devam eder |
| 7 | **F16a → R01 kapsam kararı → F16b** | Önce gerçek çıktı/suppression matrisi; sonra gerekli adaptörler. R01 helper seçilirse F16b'den sonra |
| 8 | **F10 → F14 → F15** kurulum, kapsam/yardım, landing QA | Yeni dağıtım kanalı öncesi ilk kullanım anlaşılır ve güvenli olsun |
| 9 | **F19** bulgu/karar modeli | Kapsamlı evidence üstünde stabil kimlik; JSONL/resume yalnız ölçülmüş ihtiyaçla |
| 10 | **F20 → F21a** ölçüm ve opt-in boyut cache | Hız kazanımı ve invalidation eşdeğerliği ölçülmeden cache yok |
| 11 | **R02** skills-only plugin, ihtiyaç varsa | F10/F11/F14 tamam; vendor öncesi deneme kolaylığı sağlar |
| 12 | **F21b / R03** ihtiyaç açılan genişletme | Monorepo maliyeti varsa F21b; Python/JS triyaj yükü varsa R03. Birbirinin önkoşulu değiller |
| 13 | **F17** ihtiyaç kadar modüler bakım | Stabil davranış üstünde küçük dilimler; tüm işi bekleten yeniden yazım yok |
| 14 | **R04/R05/R06/R07/R08/R10/R11** koşullu rezerv | Yalnız karttaki tetik ve bağımlılıklar oluşursa planlanır. R11 pin eskimesi veya CVE tetiklediğinde açılır |
| 15 | **R09 wizard** en son | Aktif öncelikli işler sonrası, güncel UX verisiyle yeniden tasarım |

**Bağımsız AI ölçüm hattı:** F12a sıra 1 ile aynı planlama döneminde başlayabilir; API anahtarı gerektirmez. F12b uygun backend erişimiyle, F12c ise sonuçlar yeterliyse takip eder. Bu bir paralel ajan çalıştırma talimatı değil; geliştirme bağımlılığı tarifidir. Üretim varsayılanı ölçülmeden prompt/eşik değişmez; deterministik düzeltmeler bu hattı beklemez. R04/R05 ilgili F12 kapıları tamamlanmadan açılmaz.

**Her teslimatta:** yeni davranışın testleri aynı değişiklikle gelir. Mevcut davranışa dair gerçek tüketici doğrulaması tasarımı etkiliyorsa özelliğin öncesinde yapılır; bütün-kit dogfood RC yayın kapısında kalır. F01–F08 çözümleri bir sonraki stabil yayında ilgili regression ve tüketici doğrulamasını geçmelidir. Eski roadmap'teki “cache'den sonra hemen dep-scan” sırası artık geçerli değildir.

## Birlikte değerlendireceğimiz kararlar

İlk uygulama dilimi sıra 1–4: test kapısı ve kayıt/dağıtım güvenilirliği. Planlamada öncelikle baskın kullanıcıyı (tek geliştirici/ekip/çok repo), geliştirme kapasitesini ve eksik tarama durumunun hangi ortamlarda engelleyici olacağını netleştirelim. Mevcut fail-open davranışı geliştirme akışında korunabilir; daha sıkı CI profili ayrı seçilebilir. Başlangıç kullanıcı deneyimi mi yoksa büyük monorepo maliyeti mi daha acil, F14/F21 sırasını bu veri belirlemeli.

Bu tabloda kaba eforlar birbirinden bağımsız toplam bütçe değildir; ortak schema ve test işleri örtüşür. Seçilen paket için teknik tasarım sonrası yeniden tahmin yapılmalıdır.
