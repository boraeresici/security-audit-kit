# Security Audit Kit — değerlendirme iş listesi

Kaynak: [8 Eylül 2026 çok rollü değerlendirme](application-review-2026-09-08.md). Yerel baz: `48fad91`.

**Güncelleme — 10 Eylül 2026:** 8 Eylül değerlendirmesinin ardından 3 yeni F kartı (F23–F25) ve 1 koşullu R kartı (R11) eklendi. F22 tamamlandı; kalan 24 F kartı ve 11 R kartı aşağıda yer alıyor. F23–F25 mevcut kartların boşluklarını kapatır: Python modül testleri (F09'un ön koşulu), config doğrulama (F11'in uygulama uzantısı) ve tüketici geçiş rehberi (F08'in tamamlayıcısı). R11 araç pin güncelleme otomasyonudur ve koşullu bırakılmıştır. F12 ölçüm notu eklendi: kalibrasyon skorlayıcısı implementasyonu, Qwen 3.7 Max + GLM-5.1 ilk ölçüm sonuçları ve karar kaydı. [Roadmap eşleme ve karar gerekçeleri](roadmap-reconciliation-2026-09-08.md).

**Güncelleme — 14 Eylül 2026:** SkillSpector ve UI değerlendirmesi plana işlendi: **F26** sunucusuz HTML rapor kullanılabilirliği (P2), **R12** isteğe bağlı SkillSpector pilotu (P2 aday), **R13** tarama başlatan yerel UI (koşullu). Yeni işlerin kendi sırası F26 → R12 → ihtiyaç varsa R13; mevcut P0/P1 güvenilirlik işleri önce gelir. CLI ortak yürütme katmanı olarak korunur. Önceki kart sayıları 10 Eylül kaydıdır; bu güncelleme bir F ve iki R kartı ekler.

**RC durum kontrolü — 14 Eylül 2026:** F23'ün 234 unit testi ve 93 offline e2e assertion'ı geçti. RC.1'in geçersiz `actions/setup-python` pinleri RC.2'de v6'ya düzeltildi; uzak ruleset pytest/e2e dahil beş kontrolle eşlendi ve post-merge CI yeşil çalıştı. F09 ve F23 tamamlandı. RC.2 gerçek tüketici dogfood'unda eski bootstrap'ın iki alanlı pin fallback'i, CHANGELOG hâlâ `Unreleased` olduğu için doğru biçimde reddedildi. RC.3 CHANGELOG sürümünü hazırlar ve release scriptine tag öncesi sürüm eşleşme kapısı ekler.

**Güncelleme — 11 Ekim 2026:** [Cloudflare karşılaştırması](../compare/cloudflare-security-audit-skill.md), yerel `078cf18` koduyla eşlendi. **F27** kayıtlı deep-review kapsamı ve **F28** bağımsız doğrulama pilotu eklendi; **R14** alan playbook'ları koşullu rezervdir. F11/F12/F19 kabul kriterleri genişletildi. P0/P1 sırası korunur; F19 → F27 → F28 yeni AI inceleme hattıdır. F26/R12 önceki yerinde kalır. Bunlar plan değişiklikleridir; özellikler henüz uygulanmadı.

**Güncelleme — 21 Ekim 2026:** F01 uygulaması sırasında yerel e2e'deki py-deps hataları incelendi. Neden, geliştirici shell'inde tanımlı `VIRTUAL_ENV` idi; testler hermetik yapıldı. Aynı inceleme bir ürün hatası da gösterdi: repo `.venv`'i yokken projeye ait olmayan aktif ortam denetleniyor. **F29** olarak eklendi (P1, sıra 3a). Bu bir plan değişikliğidir; düzeltme henüz uygulanmadı.

**Sıra değişikliği — 2 Kasım 2026:** F14 ve F25, F03 → F04'ün hemen arkasına (3b) alındı. Gerekçe: F02'nin kırıcı schema değişikliği ve F14'ün bağımlılığının kalkması. Önceliğin tanımı ve diğer işlerin sırası değişmedi. Planın açık bıraktığı "baskın kullanıcı / başlangıç UX'i mi monorepo maliyeti mi" kararı hâlâ verilmedi; bu değişiklik o karar yerine geçmez.

**Güncelleme — 2 Kasım 2026 (performans ve konumlandırma):** Uçtan uca ölçüm, darboğazın trivy DB indirmesi olduğunu gösterdi (`all` ~40 sn'nin ~32 sn'si); orkestratörün dili darboğaz değil. **F30** (trivy DB cache'i, sıra 3c), **F31** (pre-push profili ve paralel boyutlar) ve **F32** (README ilk ekranı, demo, karşılaştırma düzeltmesi, güven sinyalleri) eklendi. **R02** plugin kanalı P1'e yükseltildi ve 8. sıraya alındı. F14 ve F20'ye kabul kriteri eklendi. [Gerekçe](roadmap-reconciliation-2026-09-08.md).

**Not — 2 Kasım 2026:** SOCNova karşılaştırması, taramalar arası yeni açık takibi, agent/alarm entegrasyonu ve Dependabot rolü **R15** koşullu not kartına alındı. Kritik değil; teslim sırası değişmedi.

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
| F09 | Deterministik e2e'yi PR kapısı yap | Kalite / K | Tamamlandı | QA + CI | O | 5 zorunlu check uzakta etkin |
| F10 | Mevcut hook'ları koruyan kurulum ve geri alma | UX / K | P1 | DX | O | — |
| F11 | Kitin kendi güven sınırlarını ve hardening seçeneklerini çıkar | Risk / K | P1 | Güvenlik | O | — |
| F12 | Kalibrasyon hazırlığı → ölçüm → karar sözleşmesi | Araştırma / K | P1 | AI + güvenlik | B | a: yok; b: erişilebilir backend; c: ölçüm |
| F13 | Yerel/ağsız/veri paylaşımı ifadelerini düzelt | Doküman / K | P1 | Ürün + güvenlik | K | — |
| F14 | a: kapsam/kapanış özeti, yardım, kısa başlangıç; b: sessiz çıktı ve ilk bulgu satırı | UX / Ö | P1 | Ürün + DX | a: O; b: O | a: F02; b: F31b |
| F15 | Landing dayanıklılık ve erişilebilirlik kontrolü | UX / K+Ö | P2 | Frontend + QA | K | — |
| F16 | Eksik boyutları normalize kanıt modeline ekle | Geliştirme / K | P1 | Veri | B | F02, F03 |
| F17 | Shell orkestrasyonunu kademeli modüllere ayır | Bakım / Ö | P2 | Mimari | B | F09, davranış sözleşmeleri |
| F18 | Platform ve boşluklu yol test matrisi | Kalite / K+Ö | P1 | QA + DX | O | F09 |
| F19 | Bulgu kimliği ve ortak karar kaydı | Geliştirme / K+Ö | P2 | Veri + güvenlik | B | F03, F16 |
| F20 | Yerel performans ve kapsam metrikleri | Geliştirme / Ö | P2 | Operasyon + ürün | O | F02, F03 |
| F21 | a: boyut cache; b: monorepo kapsamı | Geliştirme / Ö | P2 | Performans | B | a: F03, F05, F06, F20; b: a + ihtiyaç |
| F22 | Yol haritalarını tek güncel iş listesine bağla | Bakım / K | Tamamlandı | Ürün + bakım | K | 8 Eylül: bu belge + eşleme |
| F23 | Python modülleri için unit test altyapısı | Kalite / K | Tamamlandı | QA + backend | K | F09 ile birlikte; 234 test |
| F24 | Config dosyası doğrulama ve güvenli kaynaklama | Risk / K | P1 | Güvenlik + DX | K | F11 |
| F25 | Sürüm geçiş rehberi ve breaking change bildirimi | DX / Ö | P1 | Release + DX | K | F08 |
| F26 | Sunucusuz HTML raporda arama, filtre ve bulgu detayları | Geliştirme / Ö | P2 | Raporlama + UX | K–O | F04, F14; F16 kapsam/eksiklik sözleşmesi |
| F27 | Deep incelemede kapsam defteri ve tekrar inceleme | Geliştirme / K+Ö | P2 | AI + veri | O | F03, F04, F19 |
| F28 | Bağımsız doğrulayıcı pilotu ve kapsam kontrolü | Araştırma / K+Ö | P2 | AI + QA | O pilot | F11, F12c, F19, F27 |
| F29 | py-deps: projeye ait olmayan aktif ortamı denetleme | Hata / D+K | P1 | Backend + güvenlik | K | — ; durum adlandırması F02 ile uyumlu |
| F30 | trivy DB/check cache'i, tazelik politikası, ilk koşu mesajı | Performans / D | P1 | Backend + DX | K | F03 (DB kimliği provenance'ta) |
| F31 | a: pre-push profili + push aralığında gitleaks; b: paralel boyutlar | Performans + UX / Ö | P2 | Backend + DX | a: K–O; b: O | a: F14; b: F30, F03 |
| F32 | README ilk ekranı, demo, karşılaştırma düzeltmesi, güven sinyalleri | Ürün / Ö | P1 | Ürün + DX | K–O | karşılaştırma satırı: F12b |

## Roadmap'ten gelen ek / koşullu kartlar

Bu tablo yukarıdaki F maddelerini tekrar etmez. “Koşullu” işler, belirtilen ihtiyaç ve bağımlılıklar doğrulanmadan uygulamaya alınmaz.

| ID | Eski referans / iş | Karar | Rol | Efor | Açılma koşulu / bağımlılık |
|---|---|---|---|---|---|
| R01 | T2.2 / #8 remediation compute | P1 kapsam kararı; uygulama koşullu | DX + güvenlik | K karar; O–B uygulama | Mevcut skill komutlarının yetmediği örnek |
| R02 | R5.3 skills-only plugin / manifest | P1 (2 Kasım 2026'da P2 adaydan yükseltildi) | DX + güvenlik | O | F10, F11, F14; dağıtım darboğazı (0 star) ve Semgrep'in resmi Claude Code plugin'i |
| R03 | A3 / #7 Python-JS reachability | Koşullu | Güvenlik + performans | B | F16, F21a; ölçülmüş yüksek triyaj yükü |
| R04 | L2 + Phase B provider/local runner | Koşullu | AI + mimari | B pilot; tam runner ayrıca tahmin | F12; gerçek offline/non-Claude gereksinimi |
| R05 | T3.4 generate-only PoC | Koşullu | Güvenlik + AI | B | F12c, F19; kanıt ihtiyacı |
| R06 | Python araçlarını hash-pin | Önce karar, ertelendi | Tedarik zinciri | K karar; O–B uygulama | F11; bakım/uyumluluk maliyeti kabulü |
| R07 | Tier S Layer 3 imzalı release | Ertelendi | Release + güvenlik | O | F07; yayıncı kimliği doğrulama talebi |
| R08 | A4/A5 statik situational scanner | Ertelendi | Güvenlik | Araç seçilince | Somut kapsam açığı; F16, pin/lisans incelemesi |
| R09 | CLI wizard | Son planlı özellik | DX + UX | O | Öncelikli aktif işler bittiğinde F14 verisiyle tasarım yenileme |
| R10 | T3.2 / B.1 skill extraction | Ertelendi | AI + bakım | O | R04 veya ölçülmüş bakım sorunu |
| R11 | Araç pin güncelleme otomasyonu | Koşullu | Tedarik zinciri + bakım | O | R06, F07; 3+ araç sürümü eskidiğinde veya CVE bildirildiğinde |
| R12 | SkillSpector: skill güvenliği tarama boyutu | P2 pilot adayı | Güvenlik + veri | K pilot; O entegrasyon | F11/F13; entegrasyon F02/F03/F16; varsayılan sıra F26 sonrası |
| R13 | CLI üstünde tarama başlatan yerel UI | Koşullu P2 | Backend + UX | O–B | F26 kullanım verisi; F01–F05, F11/F24; R12 kararı sonrası |
| R14 | Sinyalle seçilen uzman inceleme playbook’ları | Koşullu P2 | Güvenlik + AI | K seçim; O / alan | F12 eval kapsamı, F27; gerçek tüketicide kapsam açığı |
| R15 | Yeni açık takibi, olay çıkışı ve agent erişimi | Not / koşullu | Güvenlik + entegrasyon | a: K; b: K–O; c: O–B; d: O | a: yok; b: F01; c: F03, F19; d: c, F11, F13; gerçek tüketici talebi |

## İş kartları / kabul kriterleri

### F01 — Çalıştırma izolasyonu

Kilit bekleme süresi dolan tarama, diğer taramanın summary/SARIF/evidence/HTML dosyalarını değiştirmemeli. Her çalıştırma benzersiz dizin ve kimlik almalı; son tamamlanan çalışma işaretçisinin güncellenmesi açık bir sahiplik kuralına bağlı olmalı. İki eşzamanlı tarama ve kilit zaman aşımı testi tüm artifact'ların kendi çalışmasına ait kaldığını doğrulamalı. İptal edilmiş çalışma son başarılı kaydı bozmamalı.

**Durum:** tamamlandı, v1.19.0 ile yayımlandı (PR #32). Eski SARIF'in taşınması F03'e bırakıldı.

### F02 — Durum ve politika

Boyut sonucu en az `pass`, `findings`, `error`, `skipped`, `indeterminate`, `not_applicable` ayrımını ve nedenini taşımalı; adlandırma schema tasarımında kesinleşebilir. `gate` sonucu ayrı hesaplanmalı. Eksik Docker/uvx, eksik manifest, araç çökmesi ve soft-fail bulgusu için fixture olmalı. Mevcut tüketicilere schema geçişi belgelenmeli. Varsayılan fail-open kararını değiştirmeden yanlış `pass` giderilebilmeli.

**Karar — 2 Kasım 2026:**
- **Adlandırma:** karttaki altı ad aynen kullanıldı. `status` alanının değerleri yerinde değiştirildi ve `schema_version: 2` eklendi. Eski `fail` değeri kaldırıldı. Eski alanı koruyup yanına yeni bir alan eklemek de düşünüldü, ama o zaman eski alan atlanan boyutlar için yanlış `pass` yazmaya devam ederdi.
- **Gate:** davranış değiştirilmedi; gate hâlâ dönüş kodundan hesaplanıyor. Durum, fonksiyonun açık işaretinden (`dim_mark`/`dim_skip`/`dim_na`/`dim_error`) ya da varsayılan eşlemeden geliyor. Tarama hatalarının bloklayıp bloklamayacağı ayrı bir politika sorusu olarak açık bırakıldı.
- **Ayırt edilemeyen durumlar:** pip-audit, gitleaks, npm/pnpm/yarn audit ve guarddog, bulgu ile hata için aynı çıkış kodunu kullanıyor. Bunlar `findings` olarak kaydediliyor; bu sınırlama sözleşmede yazılı.
- **Sözleşme:** [docs/schema/summary.md](../schema/summary.md).

**Durum:** `feat/f02-status-policy` branch'inde uygulandı. e2e'ye 18 kontrol eklendi; araçlar shim'lendiği için offline ve deterministik çalışıyor. Rapordaki durum etiketleri için bir birim testi var.

### F03 — Artifact kökeni ve güncellik

Evidence yalnız aynı run manifestindeki çıktıları tüketmeli. Önceki SARIF + bu çalışmada atlanan/başarısız boyut, güncel bulgu olarak alınmamalı. Commit, dirty durumu, kapsam, araç/config/rule kimliği ve üretim zamanı için alanlar tanımlanmalı. Aynı içerikten deterministik bulgu üretimi korunmalı; çalıştırma metadata'sı ayrı tutulmalı. Eksik/bozuk çıktı görünür uyarı veya hata üretmeli.

**Karar — 2 Kasım 2026:**
- **Run manifesti:** ayrı bir dosya açılmadı; `summary.json`'daki `artifacts` alanı (bu çalıştırmanın SARIF dosyaları ve sha256'ları) bu işi görüyor.
- **Evidence ne kullanıyor:** yalnızca listedeki, hash'i tutan dosyaları; o da boyutun durumu `pass` ya da `findings` ise. Dışarıda bırakılan her dosya için bir uyarı yazılıyor ve builder bu uyarıları basıyor.
- **Ortak `sarif/`:** önceki çalıştırmaların dosyaları artık taşınmıyor; dizin her `SARIF=1` yayınında yeniden yazılıyor. Taşıma sürseydi, yükleme yapan ya da dosyayı okuyan biri eski dosyayı güncel sonuç sanabilirdi.
- **Provenance:** `summary.json`'da çalıştırma başında hesaplanıyor. Kapsadığı alanlar: commit, dirty durumu, kit sürümü ve CHECKSUMS hash'i, config hash'i, kurallar, araç pinleri, kapsam. Zaman ve run id içermiyor; evidence.json'a olduğu gibi kopyalanıyor ve aynı içerik aynı çıktıyı vermeye devam ediyor.
- **`SARIF=0` çalıştırmaları:** pre-commit gibi çalıştırmalar `sarif/` dizinine ve evidence.json'a dokunmuyor. Hangi commit'i anlattıkları provenance'ta yazılı.

**Durum:** `feat/f03-artifact-provenance` branch'inde uygulandı. e2e'ye 7, birim testlere 9 kontrol eklendi.

### F04 — Dürüst rapor

Çıkış kodu yoksa veya kapsam eksikse HTML `clean` dememeli. Araç hatası bulgu gibi sunulmamalı; sıfır gate kodu “bütün boyutlar temiz” anlamına gelmemeli. Tarama tarihi ile rapor üretim tarihi ayrılmalı. Açıkça çağrılan `report`/`evidence` üretilemediyse makine tarafından anlaşılabilir başarısızlık dönmeli; isteğe bağlı tarama sonrası rapor hatasının gate'e etkisi ayrıca belgelenmeli. Null/missing/3/1/0 durumları test edilmeli.

**Karar — 2 Kasım 2026:**
- **Sonuç satırı:** raporun başlığı tek bir sonuç gösteriyor: `clean`, `passed — bulgular var ama bloklamıyor`, `passed — NOT complete`, `blocked` (her engelleyenin adıyla; çöken araç "scan error, not a finding" olarak), `indeterminate` ya da `unknown`. `clean` yalnız iki koşul birlikte sağlanırsa yazılıyor: uygulanan her boyut bir şey denetledi ve raporlanan bulgu yok.
- **Tarama zamanı:** `summary.json`'dan alınıyor, ama yalnız summary evidence'ın kendi çalıştırmasına aitse. Bunu anlamak için `dimensions`, `artifacts` ve `provenance` karşılaştırılıyor; `scan.artifacts` bu yüzden evidence'a eklendi. Evidence'a zaman yazılmadı, böylece aynı içerik yine aynı evidence'ı veriyor. Rapor tarihi bunun yanında ayrıca gösteriliyor.
- **Açık komutlar:** `scan.sh evidence` / `scan.sh report` dosyalarını üretemezlerse 1 ile çıkıyor.
- **Tarama sonrası hata:** `SARIF=1` / `REPORT=html` ile tarama sonunda oluşan bir hata ekrana basılıyor, ama gate'i değiştirmiyor. Gerekçe: gate tarayıcıların kararıdır; render edilemeyen bir rapor onların bulduğunu değiştirmez.

**Durum:** `fix/f04-honest-report` branch'inde uygulandı.
- 15 birim testi eklendi: `verdict` için null/missing/3/1/0, `scan_time` ve başlık.
- 6 e2e kontrolü eklendi. Bunlar `main`'deki eski kodla çalıştırıldığında 6'sı da kırmızı çıktı.

### F05 — Kilit yaşam döngüsü

Canlı ve uzun süren taramanın kilidi yalnız yaşı nedeniyle alınmamalı. Release yalnız kendi token'ını taşıyan kilidi kaldırmalı. Ölü PID, PID yeniden kullanımı, heartbeat yokluğu, aynı anda stale reclaim ve INT/TERM testleri yapılmalı. Bozuk kilit dosyası sonsuz beklemeye yol açmamalı.

**Durum:** tamamlandı, v1.19.0 ile yayımlandı (PR #34).

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

**11 Ekim ek kabulü:** Scanner çalıştırma yetkisi ile hedefin build/test kodunu yürütme yetkisi ayrı belgelenmeli. Docker varlığı tek başına sandbox kanıtı sayılmaz. Repo/config/scanner metninin ajan talimatına dönüşmesi, artifact yazma sahipliği ve gizli ortam değişkenleri için tehdit senaryoları eklenmeli. F28 ilk pilotu salt kaynak incelemesi yapar; R05 yalnız PoC üretir. Gelecekte hedef kodu yürütme önerilirse ağ/ortam/yazma/kaynak sınırları ve güvenli artifact kabulü ayrı tasarım ve negatif testler gerektirir; bu kart yürütme özelliği açmaz.

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

**11 Ekim ek kabulü — karar semantiği:** F12a/F12c, kanıtla çürütülen aday ile eksik bağlam yüzünden sonuçlanmayan adayı ayırmalı. `UNCERTAIN` için somut eksik bilgi ve sonraki güvenli kontrol kaydedilmeli; hiç doğrulanmamış aday ayrı durum olmalı. FP/allowlist otomatik yan etkileri bu durumlarda oluşmamalı. Scanner severity'si korunurken AI etki hükmü ayrı alan olmalı. F12b ölçümüne kaynakta görünmeyen deployment kontrolü, yanlış kaynak izi ve hardening-only örnekleri eklenmeli. Confidence tanımı çözülmeden geçmiş Brier/ECE değerleri kalibrasyon kalitesini veya model üstünlüğünü kanıtlamaz; yukarıdaki 10 Eylül çıkarımları tarihsel gözlemdir. Eşik, karar kümesi veya üretim prompt'u bu planlama turunda değişmez.

### F13 — Veri akışı açıklaması

Her komut için yerel hesap, internet ihtiyacı ve dış servise gönderilebilecek veri türleri listelenmeli. Landing meta/karşılaştırma, README'ler ve HTML footer aynı sınırlamaları taşımalı. “Nothing leaves” gibi mutlak iddia yalnız onu gerçekten sağlayan bileşende kullanılmalı. Gerçek trafik ölçümü yapılmazsa tablo bunun kod/araç sözleşmesi incelemesine dayandığını söylemeli.

### F14 — İlk kullanım ve kapsam

Yeni kullanıcı kısa başlangıç üzerinden `doctor → scan → sonucu anla → next step` akışını tamamlayabilmeli. Yardımda her komutun boyutları, önkoşulları ve gate davranışı görünmeli. `all` dışında kalan boyutlar kapsam özetinde açık olmalı. Profiller eklenecekse mevcut varsayılanlar korunmalı. En az birkaç gerçek kullanıcıyla ilk rapora ulaşma süresi ve yanlış kapsam yorumları ölçülmeli; hedefler baz ölçüm sonrası kesinleşmeli.

**Ek — 2 Kasım 2026 (performans ve UX değerlendirmesi):**
- Her taramanın sonunda tek ekranlık bir kapanış özeti basılmalı: boyut, durum, süre, kısa neden, ardından "NOT inspected", "BLOCKED" ve önerilen sonraki adım.
- Docker çalışmıyorsa hook yine geçebilir, ama tek ve net bir satırla hangi boyutların incelenmediği ve nasıl düzeltileceği yazılmalı. Kurulum günü ile push günü farklı olduğu için bu uyarı yalnız `install.sh`'e bırakılmamalı.
- Hook bir push'u engellediğinde şunlar yazılmalı: hangi boyut, kaç bulgu, ilk dosya:satır, ham log yolu ve seçenekler (düzelt / süreli allowlist / `/sec-triage` / `--no-verify`). `error` durumunda mesaj "tarayıcı başarısız oldu, bu bir bulgu değil; allowlist'e ekleme" demeli.
- Ekrana yalnızca `say`/`warn` satırları ve bulgular gitmeli; ham çıktının tamamı log'da kalmalı. `SCAN_VERBOSE=1` eski davranışı geri getirmeli.

**Bölme — 2 Kasım 2026:** Bu ekle birlikte F14'ün eforu O'nun üstüne çıktı, bu yüzden iki parçaya bölündü:
- **F14a (3b):** kapsam ve kapanış özeti, yardım, kısa başlangıç, Docker satırı ve "error ≠ bulgu" blok mesajı. F02 verisiyle hemen yapılabilir. Boyut başına süre için `summary.json` `dimensions[]`'a eklenecek `seconds` alanı F20'den buraya alındı; ek bir alan, şemayı kırmaz. Böylece 3b, 10. sıradaki F20'yi beklemez.
- **F14b (10, F31b ile):** sessiz ekran çıktısı (`SCAN_VERBOSE`) ve blok mesajındaki "ilk dosya:satır". Hook'lar `SARIF=0` ile çalıştığı için ilk bulguyu göstermek her aracın ham çıktısını ayrıştırmayı gerektirir. Boyut çıktılarını ayrı dosyalara alan F31b altyapısıyla aynı iştir.

**F14a durumu — 2 Kasım 2026:** `feat/f14a-closing-summary` branch'inde uygulandı.
- **Kapanış özeti:** her boyutun durumu, süresi ve nedeni; komutun kapsamadığı boyutlar ("not in 'all'"); Docker ya da uvx eksikse tek satırda hangi boyutların denetlenmediği ve nasıl düzeltileceği.
- **Blok mesajı:** bloklayan bir bulgu mu, çöken bir tarayıcı mı, ayrı yazılıyor. Bulgu için seçenekler listeleniyor; çöken tarayıcı için "not a finding; do not allowlist it" deniyor.
- **`scan.sh help`:** komutlar, gate etiketleri, önkoşullar, `all`'un dışında kalanlar ve ilk kullanım yolu.
- **Süre:** `summary.json`'a boyut başına `seconds` eklendi. evidence'a kopyalanmıyor, böylece evidence'ın determinizmi korunuyor.
- **Hook'lar:** nedeni tahmin eden kendi mesajlarını bıraktı. Örneğin pre-commit, gitleaks çöktüğünde de "secret in staged changes" diyordu; artık kapanış özetine yönlendiriyorlar.
- **Çıktı sözleşmesi korundu:** `── run:`, `NEXT STEP`, `NOT inspected`, `BLOCKED` satırları duruyor.

**Yapılmayan:** kartın istediği gerçek kullanıcılarla ölçüm (ilk rapora ulaşma süresi, yanlış kapsam yorumları). Bunun için gerçek kullanıcı gerekiyor; ölçüm açık kalıyor.

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

**11 Ekim ek kabulü — yapılandırılmış AI kanıtı:**

- F19a kimlik/karar sözleşmesini, F19b şema doğrulama ve çıktı geçişini teslim eder. Kaynak referansı ve dirty durumu, kök neden, sıralı kaynak izi, geçerli kontroller, önkoşullar, etkilenen varlık, karar gerekçesi ve doğrulama engeli gerektiği dalda zorunlu olmalı. F19'un mevcut kaba eforu bu kapsamla tasarım sırasında yeniden tahmin edilir.
- Scanner kaydı, AI kararı, suppression politikası ve doğrulama durumu ayrılmalı. `REAL → confirmed`, `FP → rejected`, `UNCERTAIN → needs_validation` otomatik ve kayıpsız eşdeğerlik varsayılmaz; eski kayıtlar kanıtlarıyla migrate edilir, kanıtsız alanlar uydurulmaz.
- Kaynak/önkoşul değişince eski karar yeniden incelenmeli. Eski FP yalnız aynı çürütülmüş iddiaya uygulanmalı; bütün bileşeni kapsamdan çıkarmamalı. Satır kayması, değişen kontrol, aynı kök nedenin farklı kararları ve iki pakette aynı CVE fixture'ları bulunmalı.
- Mevcut Markdown yazma kaynağı korunacak mı, yoksa şemalı karar kaydına geçilip Markdown üretilecek mi açıkça kararlaştırılmalı. İki bağımsız yazma kaynağı oluşturulmaz. Geçiş F25 ile belgelenir; HTML/SARIF aynı doğrulanmış modelden türetilir.
- Validator eksik kaynak izi, geçersiz yol/satır, çelişkili karar alanları, yinelenen kimlik ve boyut sınırlarını denetlemeli. Şema başarısı bulgunun doğru olduğunu ispatlamaz; F28 kaynak iddialarını ayrıca denetler. Eski schema/renderer davranışı geçiş fixture'larıyla korunmalı.

### F20 — Önce ölçüm

Boyut bazında süre, durum nedeni, kapsam ve cache hit bilgisi yerelde üretilmeli. Küçük repo, monorepo ve büyük geçmiş fixture'larında sıcak/soğuk koşum ayrılmalı. Gizli veri veya kaynak kod metriklere girmemeli; ağ telemetrisi varsayılan olarak eklenmemeli. F21 için ölçülmüş darboğaz listesi çıkarılmalı.

**İlk ölçüm — 2 Kasım 2026:** Kitin kendi reposunda (82 dosya, 89 commit, macOS + Docker Desktop, imajlar önceden çekilmiş) her adım 3 kez çalıştırıldı. Sıcak koşu süreleri: secret ~1 sn, sast ~3 sn, container ~36 sn (soğuk 111 sn), sbom ~3 sn, `all` ~40 sn, evidence/report < 0,5 sn. Darboğaz trivy DB indirmesi; F30'a alındı. Boyut başına `seconds` alanı F14a'ya alındı (ek alan, şemayı kırmaz); F20 bunu ölçüm için kullanır. Bu ölçüm küçük repo içindir; monorepo ve büyük geçmiş fixture'ları hâlâ gerekli. Bir koşuda tekrarlanamayan bir rc=2 görüldü. Olası neden (doğrulanmadı): ölçüm sırasında aynı çalışma ağacında F03 değişiklikleri yarım duruyordu (`lib/evidence.py` düzenleniyordu, `scan.sh checksums`/`verify` çalışıyordu). F03 merge edildikten sonra temiz bir ağaçta tekrar ölçülmeli; yine görülürse incelenmeli.

### F21 — Cache / monorepo

**F21a = R5.2 slice B:** Yalnız boyut cache'i teslim edilir. **F21b = R5.4:** F21a'nın doğrulanmış input-hashing altyapısını kullanır; gerçek monorepo darboğazı varsa ayrı teslim edilir. F21b, F21a'nın çıkışını bekletmez. Kod/lockfile/config/rules/tool/advisory güncelliği değişince doğru invalidation gösterilmeli. Cache açık ve kapalı koşumlar aynı kapsamda aynı sonucu üretmeli. Monorepo ortak lockfile ve paylaşılan bileşen değişiklikleri alt ağaç taramasından kaçmamalı. Kazanç F20 bazına göre raporlanmalı; doğruluk sağlanmadan hız başarısı kabul edilmemeli.

### F22 — Tek planlama kaynağı

**Tamamlandı — 8 Eylül 2026:** F ve R kimlikleriyle tek güncel sıra oluşturuldu, eski roadmap/planlara yönlendirme eklendi, tamamlanan işler ve koşullu kalanlar eşleme belgesine işlendi. Tarihsel notlar korunuyor. R5.2 slice A yerel main'de ve yerel CHANGELOG'da Unreleased olarak kayıtlı; remote release durumu doğrulanmadı. GitHub issue/PR oluşturulmadı. Gerçek geliştirmeye geçerken kişi/tarih ve uzak yayın durumu ayrıca güncellenir.

### F23 — Python modülleri için unit test altyapısı

**Tamamlandı — 14 Eylül 2026:** `lib/` altındaki dört Python modülü (`evidence.py`, `kit_sarif.py`, `pkgcheck.py`, `report_html.py`) için `tests/unit/` altında doğrudan testler ve CI pytest işi mevcut. 234 test yerelde geçti. RC.1'de pytest işi action çözümleme sırasında başlamadı; test koduyla ilgisiz pin hatası RC.2'de düzeltildi. F09'un uzak required-check uygulaması ayrı açık kalır.

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

**Durum — 2 Kasım 2026:** `feat/f25-upgrade-notes` branch'inde uygulandı. 3b'ye alındığı için F08'den önce teslim edildi.
- **Upgrade notes zorunlu:** CHANGELOG'daki `### Upgrade notes` bölümü artık zorunlu; bölümü olmayan bir sürüm için `release.sh rc` tag kesmiyor. Değişiklik yoksa `- None.` yazılıyor.
- **`bootstrap.sh --check`:** pin ile son final sürüm arasındaki notları sürüm etiketiyle gösteriyor. Notları hedef tag'in CHANGELOG'undan, tek commit'lik shallow fetch ile okuyor. RC pin'i kendi final sürümünün notlarını da alıyor.
- **`install.sh` tekrar çalıştırıldığında:** config'e dokunmuyor, yeni ayarları adlarıyla listeliyor.
- **Politikalar:** komut ve ayarların deprecation politikası ve şema sürümleme kuralları RELEASING.md'ye yazıldı. Evidence ve summary şema dokümanlarına "Versioning" bölümü eklendi.
- **Eski evidence.json:** yerinde migrate edilmiyor, bir sonraki taramada yeniden üretiliyor. Bu yüzden bir migrasyon script'i gerekmedi.
- **Ayrıca düzeltildi:** `--check`, final yayımlandıktan sonra o sürümün daha eski RC'sini "latest" olarak öneriyordu (`sort -V` sıralaması yüzünden).

**Yapılmayan:** bugün kaldırılmış ya da yeniden adlandırılmış bir komut veya ayar yok. Bu yüzden deprecation için bir mekanizma kurulmadı; ilk ihtiyaçta politikaya göre eklenecek.

### F26 — Sunucusuz HTML rapor kullanılabilirliği

Mevcut `lib/report_html.py` ve `evidence.json` üzerine kurulur. Amaç ilk görsel kullanım ihtiyacını küçük bir teslimatla karşılamak; tarayıcıları veya AI runner'ı yeniden yazmak değil. P2 olarak güvenilirlik teslimatlarından sonra, F14 ilk kullanım akışının devamında ele alınır. F04 doğru rapor sözleşmesi önkoşuldur; F16'nın kapsam/eksiklik gösterimi kullanılır. F19 karar yazma modeli ve F21 cache bu salt okunur görünüm için önkoşul değildir.

**Kabul kriterleri:**

- Tek HTML dosyası `file://` ile açılır; sunucu, veritabanı, harici CDN/font, frontend build sistemi veya yeni runtime bağımlılığı gerektirmez.
- Metin arama; severity, araç ve karar filtreleri; açılır bulgu/kanıt ayrıntısı sağlanır. Filtrelenen adet toplamdan ayrılır; tüm filtreleri sıfırlama vardır.
- Çalıştırma kimliği/tarihi, taranan ve atlanan/hatalı boyutlar görünür kalır. “Filtreye uyan bulgu yok” temiz tarama anlamına gelmez.
- JS kapalıyken bulgular okunabilir; klavye kullanımı, dar ekran ve yazdırma desteklenir. Mevcut HTML escaping korunur; bulgu metni çalıştırılabilir HTML olarak eklenmez.
- Mevcut rapor komutu ve offline çıktı korunur. Sentetik bulgularla filtrelerin doğruluğu, kötü amaçlı metin ve eksik kanıt durumları kontrol edilir; gerçek ilk kullanımda bulguya ulaşma kolaylığı F14 ile değerlendirilir.

### R01 — Remediation compute kapsam kararı

Önce bir doğrudan, bir transitif ve bir parent-range engelli örnek üzerinden mevcut skill'in read-only komutlarıyla öneri üretilebildiğini değerlendir. Yeterliyse görev komut/prosedür netleştirmesiyle kapanır; resolver ürünü yazılmaz. Yetmiyorsa tek ekosistemle başlayacak helper tasarımı çıkar; manifest/range/fix sürümü kaynağı kanıt olarak gösterilsin. Paket kurma, build script çalıştırma veya kör force-pin otomatik adım olmasın. Diğer ekosistemlere genişleme ayrı tahminlenir. Karar F16'dan bağımsız; normalize bulguya bağlanan helper F16'ya bağlı.

### R02 — Skills-only deneme kanalı

Önce vendored scanner bulunan/bulunmayan repo ve farklı çalışma dizini sözleşmesi yazılsın. Plugin kiti otomatik indirmesin, hook/config'i sessiz değiştirmesin; eksik tarayıcı için temiz önkoşul açıklaması üretsin. Manifest, sürüm, kök çözümleme ve izin bildirimi hedef host üzerinde test edilsin; `allowed-tools` tek başına sandbox garantisi diye sunulmasın. Deterministik tarayıcı vendored+pinned kalsın. Claude kanalının açılması tam Phase B gerektirmez; başka host desteği ayrıca talep ve test ister.

**Öncelik değişikliği — 2 Kasım 2026:** P2 adaydan P1'e yükseltildi; teslim sırasında 11'den 8'e, F10'un hemen arkasına alındı. Gerekçe: dağıtım ana darboğaz. Repo 4,5 ayda 0 star aldı, kit hiçbir plugin marketplace'inde yok. Aynı kanalda doğrudan rakipler var: Semgrep'in resmi Claude Code plugin'i (MCP + hook + skill, agent'ın ürettiği her dosyayı tarar, `/plugin` Discover sekmesinde; Semgrep hesabı gerektirir) ve Trail of Bits'in `static-analysis` plugin'i (CodeQL + Semgrep + SARIF birleştirme). Ayrışma noktası olarak kitin pinli/checksum'lı tedarik zinciri, `skipped ≠ pass` durum sözleşmesi, kurulum öncesi `pkgcheck` hook'u ve hesap gerektirmemesi öne çıkarılmalı. Kabul kriterleri değişmedi; `.claude-plugin/marketplace.json` ile tek komutla kurulum hedeflenir, `bootstrap.sh` ile vendor'lama seçenek olarak kalır.

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

### R12 — SkillSpector pilotu ve isteğe bağlı entegrasyon

Agent'a yüklenen skill paketlerinin güvenliği, mevcut uygulama SAST/SCA ve `sec-ai-review` kapsamını tamamlayan somut adaydır. R08'den ayrı bu kartta izlenir; aynı iş için ikinci genel scanner kartı açılmaz. Kaynaklar: [SkillSpector README](https://github.com/NVIDIA/SkillSpector) ve [paket tanımı](https://github.com/NVIDIA/SkillSpector/blob/main/pyproject.toml), 14 Eylül 2026 incelemesi. Statik ve isteğe bağlı LLM analizi, JSON/SARIF çıktıları mevcut; Python 3.12+ ve LLM/YARA bağımlılıkları izole kurulum gereksinimini destekliyor. Uygulama öncesi seçilen commit'in lisans, bağımlılık ve çıktı sözleşmesi yeniden doğrulanır. Bu planlama turunda araç kurulmadı veya çalıştırılmadı; kalite ölçümü yok.

**R12a — Pilot (K):** F26 sonrasında, F11/F13 veri ve güven sınırlarıyla kitin `skills/` içeriği ve sentetik benign/kötücül skill fixture'ları üzerinde sabit sürüm/commit ile statik tarama ölçülür. Özellikle saldırı örneği anlatan güvenlik skill'lerinin yanlış pozitifleri, bilinen kötü örneklerin kaçırılması, süre ve kurulum maliyeti kaydedilir. Fixture taranan veri olarak kalır, içindeki talimatlar yürütülmez. Pilotun ölçülebilir kabul eşikleri koşumdan önce yazılır; yetersiz faydada entegrasyon ertelenir. Bu ayrı pilot tüm F16 adaptörlerinin bitmesini gerektirmez.

**R12b — Adaptör (O, pilot başarılıysa):**

- Önerilen `scan.sh skills` girişi isteğe bağlıdır; ilk sürüm `all`, pre-push ve otomatik kurulum kapısına eklenmez. Komut henüz mevcut değildir.
- Araç ayrı, pinli ortamda çalışır; kitin temel kurulumuna Python/LLM bağımlılıkları yüklenmez. Eksik araç, hedef yokluğu, hata ve bulgu durumları F02 sözleşmesiyle ayrılır.
- İlk kapsam repo içindeki açıkça seçilmiş skill dizinleridir; kullanıcının global skill/config/env dosyaları otomatik taranmaz. Skill yalnız `SKILL.md` değil, ilişkili paket dosyalarıyla ele alınır.
- Varsayılan `--no-llm`; dış model kullanımı açık seçimdir. Statik analiz tamamen ağsız diye sunulmaz: OSV dahil ağ/veri davranışı F13'e yazılır.
- JSON/SARIF sonuçları F03/F16 üzerinden aynı çalıştırmanın `evidence.json` ve HTML çıktısına normalize edilir. Araç/rule, dosya/satır, tarama modu ve özgün risk bilgisi korunur; risk skoru CVSS veya kitin REAL kararı yerine geçmez.
- Başlangıç yalnız raporlama. Baseline otomatik toplu kabul edilmez; pre-install/hard gate ancak ayrı politika kararı ve yanlış pozitif/kaçırma ölçümüyle açılır. LLM modu eklenirse kalite ve belirsizlik F12 ile ayrıca değerlendirilir.

### R13 — Tarama başlatan yerel UI (koşullu)

F26 raporu günlük kullanımı karşılamaz ve kullanıcı tarama başlatma/ilerleme takibinde somut ihtiyaç gösterirse açılır. Varsayılan plan sırası R12 pilot kararından sonradır; SkillSpector'ın entegrasyonu teknik önkoşul değildir, pilot elenirse UI engellenmez. CLI ve hook/CI davranışları ortak yürütme yolu olarak kalır.

**İlk dilim:** Tek repo, tek aktif tarama, sabit kapsam seçenekleri, başlat/durum/log/sonuç ekranı. Küçük yerel Python servis mevcut `scan.sh` komutlarını çağırır; ekran ortak evidence çıktısını okur. Framework seçimi uygulama sırasında yapılır. İlk sürümde merkezi hosting, kullanıcı yönetimi, çok-repo paneli, veritabanı ve UI'den suppression/fix yazma yoktur.

**Kabul kriterleri:**

- F01–F05 çalışma izolasyonu, iptal/hata ve son tamamlanan sonuç ayrımı doğrulanmıştır. Canlı çalışma ile eski sonuç aynı tarama gibi gösterilmez.
- Servis yalnız loopback'e bağlanır; Host/Origin ve oturum token'ı kontrolleriyle başka web sayfalarının tarama başlatması engellenir. Sabit komut/argüman listesi kullanılır; UI girdisi shell komutuna birleştirilmez.
- Repo kökü başlangıçta açıkça seçilir; API keyfi dosya okuma veya config/env içeriği sunmaz. F11/F24'teki çalıştırılabilir repo config sınırı kullanıcı akışında ele alınır; sözdizimi kontrolü sandbox sayılmaz.
- Temiz/bulgulu/hatalı/atlanan tarama, eşzamanlı başlatma ve yetkisiz istek akışları sınanır. Kurulum ve ilk sonuç akışı belgelenir; isteğe bağlı UI bağımlılıkları CLI kurulumunu büyütmez.
- `sec-triage`/deep review otomatik UI kapsamına girmez. Agent çalıştırma ihtiyacı oluşursa R04 ayrı kalite/runner kararıdır; bulgu kararı yazmak F19'a bağlı ayrı teslimattır.

F26/R13 ile R09 wizard aynı onboarding ihtiyacına iki çözüm olarak otomatik geliştirilmez. UI kullanım verisi wizard gereğini yeniden değerlendirir; R09 son planlı özellik konumunu korur.

### F27 — Deep incelemede kapsam defteri

İlk teslimat yalnız opt-in whole-repo/deep akışıdır; rutin taramaya ajan maliyeti eklenmez. Mevcut component/class planı, run'a bağlı makinece doğrulanabilir kapsam kaydına çevrilir. Yeni DB veya resume motoru gerekmez.

**Kabul kriterleri:**

- Birim kimliği yüzey, güven sınırı, bileşen ve inceleme sınıfından deterministik üretilir. İncelenen yollar, kontrol edilen güvenlik koşulu, sonuç, kanıt, sorumlu inceleme ve aday kimlikleri kaydedilir; boş “incelendi” beyanı yeterli değildir.
- Planlanan, süren, tamamlanan, engellenen, ertelenen, aday içeren ve kapsam dışı iş ayrılır. Atlanan iş temiz sayılmaz. Birim/aday referansları ve durum geçişleri validator ile kontrol edilir.
- Önceki run yalnız ilgili kaynak ve koşullar karşılaştırılarak kullanılır. Değişmiş kaynak ve çözülmemiş engel yeniden iş açar. Scanner cache'i AI kapsam kanıtı yerine geçmez.
- Kapsam seçimi, süre/çağrı bütçesi ve kapanış nedeni raporda görünür. Bütçe nedeniyle incelenmemiş aday, doğrulanmış belirsiz adayla karışmaz; rapor kısmi kalır. Bütçe yoksa yapay sınır üretilmez.
- Fixture'lar: aynı kaynak, yalnız satır kayması, kontrol değişikliği, kapsam daraltma, yarım kalan inceleme, yinelenen birim ve referanssız aday. F04/F26 raporu kapsam boşluğunu gösterir; yeni dashboard gerekmez.

### F28 — Bağımsız doğrulayıcı ve kapsam kontrolü

**F28a — P2 pilot:** Mevcut host'un ayrı bağlam/ajan yeteneğini kullanarak aday için keşiften bağımsız kaynak incelemesi ölçülür. Yeni provider runner (R04) önkoşul değildir. Ayrı bağlam sağlanamıyorsa bağımsız doğrulama yapılmadığı açıkça kaydedilir; self-review bağımsız diye etiketlenmez.

**Kabul kriterleri:**

- Doğrulayıcı kimliği keşif sahibinden farklıdır; adayın kaynak referanslarını ve en güçlü karşı kanıtı yeniden okur. Kaynak incelemesi ile yürütülmüş test kanıtı ayrılır; pilot hedef kod çalıştırmaz ve otomatik fix/allowlist yazmaz.
- Son karar F19 şemasına uyar. Doğrulama hatası veya bütçe bitmesi olumlu karar üretmez. Ortak artifact'ı yalnız koordinatör yazar; incelemeler izole sonuç döndürür. Maddi kaynak/karar değişikliği yeni kontrol gerektirir.
- F12 ile aynı sürümlü veri/split üzerinde mevcut sweep ile pilot karşılaştırılır: REAL precision/recall, abstention, tamamlanma oranı, çağrı/token ve süre. Hatalı konum, gözden kaçan koruma, kaynak metnindeki talimat enjeksiyonu ve abartılmış etki negatif örnekleri olmalı. API erişimi yoksa pilot ölçülmedi olarak kalır.
- Varsayılan akışa geçiş yalnız ölçülen fayda/maliyet kararıyla yapılır. Bu plan ücretli eval başlatmaz.

**F28b — Koşullu devam:** F28a yararlıysa F27 defterine karşı bağımsız kapsam kontrolü ve son kayıt kontrolü eklenir. Keşif sayısını artırmak tek başına kapsam başarısı sayılmaz. Bütçede doğrulama/kapanış için pay ayrılır; yetişmeyen işler görünür kalır. İki kontrolü her rutinde zorunlu kılma kararı ayrıca ölçülür.

### R14 — Uzman alan playbook'ları (koşullu)

Gerçek tüketicide mevcut skill/scanner'ların kaçırdığı kaynak inceleme ihtiyacı varsa tek alanla başla. Adaylar: HTTP/auth protokol uyuşmazlığı, RPC/queue yetkisi, veri silme/restore/tenant yaşam döngüsü, browser veya mobile/IPC. Native/kernel/binary kapsamı otomatik ürün hedefi değildir.

Seçilen alan için giriş sinyali, incelenecek sınırlar, uygulanmama nedeni, en az bir gerçek bulgu/FP ikizi ve kaynak referansları hazırlanmalı. Yeni kurallar F12 dev ölçümüne, kapsam F27'ye bağlanmalı. R10 ile yalnız ihtiyaç duyulan referanslar ayrılmalı; tüm skill ağacı yeniden düzenlenmez. Yeni scanner, canlı test veya exploit yürütme eklenmez. Kod/metin alınacaksa uygulama tarihinde sürüm ve lisans doğrulanıp atıf korunur.

### R15 — Yeni açık takibi, olay çıkışı ve agent erişimi (not)

**Kayıt — 2 Kasım 2026:** Kullanıcı sorusundan doğdu: bağımlılıklarda yeni yayınlanan açıklar için tarama arasında da uyarı alınabilir mi, sonuç bir AI agent'a (MCP vb.) ve alarm/observer araçlarına bağlanabilir mi. SOCNova (yapay zekâ destekli SOC platformu, socnova.com) karşılaştırmasında kite alınacak yeni çekirdek özellik bulunmadı: AI triyaj, FP ayıklama, tehdit skoru ve vaka kaydının karşılıkları (`/sec-triage`, allowlist decay, KEV/EPSS, `findings-<tarih>.md`) mevcut. CLI'ya ek web UI F26 → koşullu R13 kararıyla zaten planda. Bu kart şu an kritik değil; sıra değiştirmez, aşağıdaki tetiklerle yeniden değerlendirilir.

**Bugünkü boşluk:** Tarama yalnız commit/push/elle çalışıyor. Kod değişmeden bağımlılığa yeni açık yayınlanırsa bir sonraki taramaya kadar görünmez. Kitin kendi repo'sundaki haftalık self-audit tüketici için şablon değil.

**Aşamalar ve koşullar:**

- **R15a — Dependabot rehberi (doküman):** GitHub tüketicisine Dependency graph, Dependabot alerts / security updates, `dependabot.yml` ve auto-triage kurulumunu ve kitle iş bölümünü (Dependabot sürekli tetik; kit reachability, KEV/EPSS, fix maliyeti, Dependabot PR'ının guarddog/pkgcheck kapısı) anlatır. Kit kullanımını doğrudan artırmaz; “taramalar arası boşluk ne olacak” sorusunu cevaplar. F14 yardım/kapsam işiyle birlikte ele alınabilir. Ayrıca kitin kendi repo'sunda `.github/dependabot.yml` yok; `github-actions` ekosistemi SHA pinli action'ları izleyebilir (R11 ile ilişkili, docker/pyrun araç pinlerini kapsamaz).
- **R15b — Zamanlanmış tüketici CI şablonu:** Günlük `SARIF=1 scan.sh osv` + deps, yalnız rapor, build kırmaz. GitHub'da SARIF Code Scanning'e yüklenir; yeni/kapanan uyarı takibi ve bildirimi GitHub yapar.
- **R15c — Fark ve olay çıkışı:** `evidence_diff` (yeni / çözülen / devam eden; `indeterminate` boyutta “çözüldü” yok, ilk koşu baseline), yalnız yeni CVE'ler için KEV/EPSS, JSONL (SIEM / SOCNova), Prometheus textfile metrikleri (observer/alarm araçları), isteğe bağlı webhook. Dependabot uyarılarıyla tek kuyruk GHSA↔CVE alias eşlemesi gerektirir. Kit ağa çıkmaz; dış gönderim ayrı adımdır ve F13 tablosunda yer alır. F03 ve F19 olmadan satır kayması sahte “yeni” üretir.
- **R15d — Salt okunur MCP sunucusu:** `get_summary`, `list_findings`, `get_finding`, `diff_since`, `coverage_gaps`; yerel stdio, opsiyonel bileşen. Tarama başlatma ve karar yazma MCP'ye açılmaz: bulgu metni taranan koddan gelir (prompt injection, F11) ve kararların tek kaynağı `findings-<tarih>.md` kalır.

**Açılma tetiği:** Gerçek bir tüketicinin taramalar arası açık bildirimi veya alarm/agent entegrasyonu talebi. R15a doküman olduğu için F14 sırasında tetik beklemeden alınabilir.

### F29 — py-deps ortam seçimi

**Bulgu — 21 Ekim 2026 (D+K):** `scan_py_deps()` (`scan.sh:252`), repoda `.venv` yoksa aktif `$VIRTUAL_ENV`'i projenin ortamı kabul ediyor (`scan.sh:264`). Bu değişkenin bu repoya ait olup olmadığına, hatta gerçek bir venv olup olmadığına bakılmıyor. Aynı fonksiyonun yorumu başka projenin ortamını denetlemeyi “sessizce yanlış cevap” diye tanımlıyor; repo `.venv`'i varken bu kural uygulanıyor, yokken uygulanmıyor. Geliştirici makinesinde `VIRTUAL_ENV` pyenv'in global yorumlayıcısını (`~/.pyenv/versions/3.12.9`) gösterirken, venv'siz yalnız `pyproject.toml` içeren fixture'da beklenen INDETERMINATE yerine global yorumlayıcı denetlendi. pip-audit `Dependency not found on PyPI` hatası verdi ve gate HARD blokladı (rc=1). Aynı yol, temiz bir yabancı ortamda yanlış `pass` da üretebilir; bu ikinci sonuç kod yolundan çıkarımdır, ayrıca ölçülmedi. CI'da `VIRTUAL_ENV` tanımlı olmadığı için e2e bunu görmüyordu; e2e F01 branch'inde `unset VIRTUAL_ENV` ile hermetik yapıldı, ürün davranışı değişmedi.

**Kabul kriterleri:**

- Aktif `VIRTUAL_ENV` yalnız bu repoya bağlanabiliyorsa (ör. yolu `ROOT` altında) proje ortamı sayılmalı. Bağlanamıyorsa davranış açıkça seçilmeli: no-env yoluna düşmek (statik manifest okuma veya INDETERMINATE) ya da açık bir opt-in değişkeniyle kabul etmek. Seçim ve gerekçe karta işlenmeli.
- `pyvenv.cfg` taşımayan (venv olmayan) bir `VIRTUAL_ENV` venv sayılmamalı.
- Projeye ait olmayan ortam denetlenmişse bu sonuç `pass` veya HARD bulgu olarak raporlanmamalı. Çıktı hangi ortamın denetlendiğini ve neden seçildiğini söylemeli; `summary.json` durumu F02'nin durum adlandırmasıyla uyumlu olmalı.
- Fixture'lar: repo `.venv` + yabancı `VIRTUAL_ENV` (mevcut test korunur), `.venv` yok + yabancı gerçek venv, `.venv` yok + venv olmayan yorumlayıcı (pyenv global örneği), `.venv` yok + `ROOT` altındaki venv, `VIRTUAL_ENV` tanımsız.
- Mevcut kullanıcılar için davranış değişikliği CHANGELOG'da ve F25 geçiş notunda belirtilmeli; README/README-tr'deki ortam seçimi açıklaması güncellenmeli.

**Karar — 2 Kasım 2026:** Sıra `PY_VENV` > repo `.venv` > aktif `VIRTUAL_ENV`. Aktif ortam ancak `pyvenv.cfg` taşıyorsa ve fiziksel yolu (symlink çözülmüş) `ROOT` altındaysa proje ortamı sayılır. Diğer durumlarda neden yazılır ve no-env yoluna düşülür: statik manifest ya da INDETERMINATE. Yabancı ortamı kabul etmek için iki seçenek vardı: `VIRTUAL_ENV`'e güvenen bir bayrak ya da yol veren `PY_VENV`. Yol veren seçildi. Kullanıcı hangi ortamı denetlettiğini adıyla söylüyor; bayrak ise yine shell'in o an aktif ettiği şeye bağlı kalırdı. `PY_VENV` açık bir seçim olduğu için sonucu normal pip-audit sonucu gibi sayılır; denetim satırı ortamı ve seçilme nedenini yazar. `bin/python` içermeyen bir `PY_VENV` hatadır (rc=1); sessiz fallback yapılmaz. Yeni durum adı eklenmedi: üretilen sonuçlar mevcut `pass`/`findings`/`indeterminate`, F02'nin adlandırmasıyla çakışmıyor. F25'in rehberi henüz yazılmadığı için geçiş notu CHANGELOG'daki "Upgrade notes" altında.

**Durum:** uygulandı, PR #38 ile `main`'de (yayımlanmadı). e2e'ye 9 kontrol eklendi; kabul kriterlerindeki beş fixture ve `PY_VENV` için iki durum test ediliyor. Ölçülen pyenv-global vakası artık rc=0 ve INDETERMINATE.

### F30 — Tarayıcı veritabanı cache'i (trivy)

**Bulgu — 2 Kasım 2026 (D):** Bu repo üzerinde 3 tekrarlı uçtan uca ölçüm yapıldı. `scan.sh all` sıcakken ~40 sn sürüyor; bunun ~32 sn'si `scan_container`'ın (`scan.sh:521`) trivy'yi cache volume'u olmadan `docker run --rm` ile çalıştırmasından geliyor. Her koşuda 131 MiB'lık vuln DB ve misconfig check bundle'ı yeniden indiriliyor. İndirilen bundle pinli 0.58 tarafından parse edilemediği için log'a rego ERROR satırları düşüyor. Soğuk ilk koşu 111 sn sürüyor ve bunu açıklayan bir mesaj yok. Python son işleme < 0,5 sn, bash'in kendi payı ~0,3 sn; yani orkestratörün dili darboğaz değil. Bu, F21a'nın sonuç cache'inden ayrı bir *araç veritabanı* cache'idir ve input-hashing gerektirmez.

**Kabul kriterleri:**

- trivy DB ve check bundle'ı kalıcı bir cache'te tutulmalı (varsayılan: named docker volume; CI için host yolu ile değiştirilebilir). Bir tazelik eşiği altında `--skip-db-update --skip-check-update` kullanılmalı, eşik aşılınca DB yenilenmeli. Varsayılan eşik ve gerekçesi karta işlenmeli.
- `SCAN_OFFLINE=1` desteklenmeli: cache'te DB yoksa boyut `pass` değil `skipped`/`not inspected` olmalı (F02 durum adlandırması).
- Bayat bir DB ile alınan "temiz" sonuç, taze bir DB ile alınandan ayırt edilebilmeli. Bunun için iki ayrı yer var:
  - **DB'nin kimliği** (trivy DB metadata'sındaki `UpdatedAt`) provenance'a (F03) yazılmalı. Aynı DB her zaman aynı değeri verir; bu yüzden `evidence.json`'a kopyalanabilir ve "aynı içerik aynı çıktıyı verir" garantisi korunur.
  - **DB'nin yaşı** (kaç saat önce güncellendiği) yalnız `summary.json`'daki çalıştırma bilgilerine ve `doctor` çıktısına yazılmalı. Provenance'a yazılmamalı: yaş her çalıştırmada değişir ve evidence'ı her seferinde farklı kılar.
- İlk koşuda tek satırlık bir açıklama basılmalı ("first run: downloading the trivy vulnerability DB (~130 MiB, once)"). trivy `--no-progress` ile çalıştırılmalı; rego ERROR satırları log'dan kalkmalı.
- Kazanç, aynı ölçüm yöntemiyle önce/sonra olarak raporlanmalı (tahmin: `all` ~40 sn → ~9 sn). Cache açık ve kapalı koşumlar aynı bulguları üretmeli.
- İsteğe bağlı: `scan.sh warm` (imaj çekme + DB indirme), `install.sh` sonunda önerilir; böylece ilk pre-push dakikalar sürmez.

**Karar ve durum — 3 Kasım 2026:** `feat/f30-trivy-db-cache` branch'inde uygulandı.
- **Cache:** varsayılan olarak `security-audit-trivy` adlı bir docker volume. `TRIVY_CACHE` mutlak bir yol olarak verilirse o dizin bind mount ediliyor (CI için). Disk kullanımı ~1,7 GB: 130 MiB'lık indirme açıldığında bu boyuta çıkıyor. Bu, README'de ve yükseltme notunda yazıyor.
- **Tazelik eşiği:** `TRIVY_DB_MAX_AGE_H=24`. Gerekçe: upstream DB'yi günde bir kez yeniden üretiyor (DB metadata'sında `NextUpdate` = `UpdatedAt` + 24 saat). Daha sık yenilemek yeni bir şey getirmez, daha seyrek yenilemek yeni advisory'lerin gecikmesine yol açar.
- **Check bundle:** hiç indirilmiyor (`--skip-check-update`). Pinli trivy'nin içine gömülü check'ler kullanılıyor. Bu hem rego ERROR satırlarını kaldırıyor hem de sonucun tekrarlanabilir olmasını sağlıyor.
- **DB kimliği ve yaşı:** kimlik (`UpdatedAt`) provenance'a ve oradan evidence'a gidiyor. Yaş yalnız `summary.json`'daki `trivy_db` alanına, `doctor` çıktısına ve kapanış tablosuna yazılıyor.
- **`SCAN_OFFLINE=1`:** cache'te DB yoksa boyut `skipped` oluyor; varsa yaşına bakılmadan offline tarama yapılıyor.
- **Ölçüm:** kitin kendi reposunda, gerçek araçlarla, üçer çalıştırma.
  - Önce: `all` 46–58 sn, container 39–49 sn.
  - Sonra: `all` 6,5–9,6 sn, container 2,0–2,4 sn.
  - İlk (soğuk) çalıştırma 42 sn sürüyor; bu süre DB indirmesinden geliyor ve bir kez ödeniyor.
  - Cache açık ve kapalı çalıştırmalar aynı bulguları verdi (2/2). Cache'li çalıştırmada indirme ve ERROR satırı yok.
- **Testler:** 11 e2e kontrolü önce yazıldı ve kırmızıydı. Docker shim'i ile ilk çalıştırma, taze DB, bayat DB, iki offline durumu, mutlak yol cache, evidence, `doctor` ve `warm` test ediliyor.

### F31 — Hook profili ve paralel boyutlar

**Bulgu — 2 Kasım 2026 (Ö):** pre-push bugün `all`'u çalıştırıyor. Bloklamayan (soft) `container` boyutu tek başına sürenin ~%90'ı. gitleaks her push'ta tam geçmişi tarıyor; büyük geçmişlerde bu dakikalar sürebilir. Boyutlar sırayla çalışıyor.

**Kabul kriterleri:**

- **F31a — pre-push profili:** pre-push'ın hangi boyutları çalıştırdığı açık bir profil olmalı; varsayılanı ve gerekçesi karta işlenmeli. Profilin dışında kalan boyutlar kapanış özetinde "bu profilde çalışmadı" olarak görünmeli (F14). gitleaks pre-push'ta push aralığını (`--log-opts`) tarayabilmeli, ama **varsayılan tam geçmiş kalır**; aralık taraması büyük geçmişi olan repolar için açıkça açılan bir seçenektir. Gerekçe: aralık taraması, kit kurulmadan önce push edilmiş bir sırrı pre-push'ta görmez; varsayılanı daraltmak gate'in kapsamını sessizce azaltır. Aralık açıkken kapanış özeti bunu "secret: push aralığı" diye yazmalı. Tarandığı aralık provenance'ta (`scope`) yazılı olmalı. Yeni branch ve uzak ref'i olmayan durumların testleri gerekli.
- **F31b — paralel boyutlar:** F30'dan sonra yapılmalı (cache öncesi tahmini kazanç yalnız ~4 sn). Kilit parent süreçte kalmalı; boyut çıktıları ayrı dosyalara yazılıp sabit sırada log'a basılmalı; `summary.json` boyut sırası deterministik olmalı (F03). Ctrl-C'de arka plan süreçleri ve docker container'ları temizlenmeli. `SCAN_PARALLEL=0` sıralı davranışı geri getirmeli.

### F32 — Dış okuyucu için ilk izlenim ve güven sinyalleri

**Bulgu — 2 Kasım 2026 (Ö):** Repo 16 Haziran 2026'da açıldı; 2 Kasım itibarıyla 0 star, 0 fork. README 733 satır ve ilk ekranda bir mermaid diyagramı var; "kur → tara → sonucu gör" akışını gösteren kısa bir demo yok. `docs/compare/aikido-semgrep.md:100` varsayılan Claude backend'i için "credit balance is too low" yazıyor; yani projenin en güçlü farkı (kanıt barı + eval) ölçülmemiş halde yayında. `docs/compare/cloudflare-security-audit-skill.md` Türkçe olduğu için dış okuyucuya kapalı. Bağımsız bir güven sinyali (OpenSSF Scorecard, imzalı release, kullanım hikâyesi) yok.

**Kabul kriterleri:**

- README'nin ilk ekranı: ne yaptığı, tek kurulum komutu ve 60 sn'lik bir terminal kaydı (asciinema/GIF). Derin içerik `docs/`'a taşınmalı; README-tr aynı yapıyı izlemeli.
- Karşılaştırma tablosundaki ölçülmemiş satır, F12b ölçümüyle doldurulmalı ya da ölçülene kadar kaldırılmalı.
- Public `docs/compare` belgeleri İngilizce olmalı ya da iç planlamaya taşınmalı.
- OpenSSF Scorecard eklenmeli; imzalı release R07 kararına bağlı kalır.
- Aikido/Semgrep karşılaştırması landing'in ana bölümünden çıkarılmalı; rakip olarak agent kanalındaki araçlar (Semgrep plugin, Trail of Bits `static-analysis`) esas alınmalı.

## Güncel teslim sırası — ana planlama kaynağı

Aşağıdaki sıra tek ekip için önerilen varsayılandır; aynı satırdaki işler tek PR olmak zorunda değil. Koşullu işler açılmadığında sonraki bağımsız işi bekletmez. Önceki Paket A/B/C sırası bu tabloyla değiştirilmiştir.

| Sıra | Teslimat | Neden şimdi / bitiş kapısı |
|---|---|---|
| 0 | **F22 tamamlandı** | Tek sıra ve roadmap eşlemesi hazır |
| 1 | **F09 + F23 tamamlandı** | 234 unit test, 93+ offline e2e assertion; pytest/e2e dahil beş required check uzakta etkin. F01–F06 regresyonları ilgili düzeltmeyle eklenir |
| 2 | **F01 → F05** çalıştırma izolasyonu ve kilit sahipliği | Cache ve rapor öncesi ortak kayıt yarışlarını gider |
| 3 | **F02 → F03 → F04** durum, güncel kanıt, doğru rapor | Eksik/eskimiş tarama temiz görünmesin; F01 ve F02 schema tasarımı beraber yapılır. F23'teki unit test fixture'ları F02–F04 düzeltmeleriyle genişletilir |
| 3a | **F29** py-deps ortam seçimi | Yabancı ortamın sonucu bu repoya ait gibi raporlanmasın; durum adlandırması F02 ile uyumlu olsun. Küçük ve bağımsız, F02 sonrasını beklemeden de alınabilir |
| 3b | **F14a + F25** kapsam özeti/yardım ve sürüm geçiş rehberi | 2 Kasım 2026'da 8. ve 4. sıradan öne alındı. F02, `summary.json` için kırıcı bir schema değişikliği getirdi; tüketicinin geçiş rehberi bu değişikliği içeren sürümle birlikte çıkmalı. F14'ün tek bağımlılığı F02 idi; F02'nin ürettiği durum ve nedeni kullanıcıya okunur bir kapsam özeti olarak göstermek bu işin özü. Yayın kapısı (F06–F08) bunlardan sonra gelir |
| 3c | **F30** trivy DB cache'i | 2 Kasım 2026'da eklendi. Ölçülmüş tek büyük darboğaz (`all` ~40 sn'nin ~32 sn'si); küçük ve bağımsız. DB kimliğini provenance'a yazdığı için F03'ten sonra gelir; F29 gibi araya alınabilir |
| 3d | **SAST'tan tarama çıktılarını hariç tutma (yapıldı, `dev/plugin-readiness`) + dogfood otomasyonu** | 3 Kasım 2026'da eklendi (v1.20.0 dogfood). Bu sürümün iki hatasını otomatik yakalayacak senaryolar: sıfırdan kurulum ve eski pinden yükseltme. Plugin'e giden yolun ilk adımı |
| 4 | **F06 → F08 (+F07) → F10 → F24/F11 (plugin kısmı)** cache politikası, kanal, kurulum ve config sınırı (F25 3b'ye alındı; F10 3 Kasım 2026'da 8'den alındı) | Bir sonraki stabil yayın için güvenilirlik kapısı; F07 zorunlu kontrollerine F09 dahil. F25 tüketicinin sürüm geçişinde ne yapacağını bilmesini sağlar |
| 5 | **F13 + F11 + F24** veri akışı, kit tehdit modeli ve config doğrulama | Yanlış yerellik iddiasını gider; F24 config'in çalıştırılabilir doğasını somut kontrol altına alır. R02/R06 için sınırları tanımla |
| 6 | **F18** platform/yol matrisi ve kalan WSL2 doğrulaması | Taşınabilirlik temel ürün vaadi; WSL2 ortamı yoksa diğer testler devam eder |
| 7 | **F16a → R01 kapsam kararı → F16b** | Önce gerçek çıktı/suppression matrisi; sonra gerekli adaptörler. R01 helper seçilirse F16b'den sonra |
| 8 | **R02 (önce yerel/özel marketplace) → R02 herkese açık + F32 → F15** plugin kanalı, ilk izlenim ve landing QA (F10 4'e, F14 3b'ye alındı) | Yeni dağıtım kanalı öncesi ilk kullanım anlaşılır ve güvenli olsun. R02 2 Kasım 2026'da 11. sıradan buraya alındı: dağıtım ana darboğaz. F32'nin karşılaştırma satırı F12b ölçümünü bekler; geri kalanı beklemez. F31a pre-push profili F14a ile birlikte ya da burada alınabilir |
| 8a | **F26** sunucusuz HTML rapor kullanılabilirliği | F04/F14 ve F16 kapsam sözleşmesi üstünde ilk görsel kullanım; F19/cache/agent runner beklemez |
| 8b | **R12a → koşulu sağlanırsa R12b** SkillSpector | Önce fixture tabanlı fayda/yanlış pozitif ölçümü, sonra pinli opsiyonel adaptör; varsayılan gate değişmez |
| 9 | **F19a → F19b** bulgu/karar ve kanıt sözleşmesi | Stabil kimlik, belirsizlik, şema doğrulama ve geriye uyum; JSONL/resume yalnız ölçülmüş ihtiyaçla |
| 9a | **F27 → F28a → koşulu sağlanırsa F28b** deep inceleme kalitesi | Kapsam kaydı ardından bağımsız doğrulama pilotu; F28 ayrıca F12c bekler. Bu AI hattı bağımsız F20/F21 işlerini bloke etmez |
| 10 | **F20 → F31b + F14b → F21a** ölçüm, paralel boyutlar, sessiz çıktı ve opt-in boyut cache | Hız kazanımı ve invalidation eşdeğerliği ölçülmeden cache yok. F31b yalnızca F30'dan sonra anlamlı bir kazanç sağlar; F14b aynı çıktı altyapısını kullanır |
| 11 | *(R02 8. sıraya alındı)* | — |
| 12 | **F21b / R03** ihtiyaç açılan genişletme | Monorepo maliyeti varsa F21b; Python/JS triyaj yükü varsa R03. Birbirinin önkoşulu değiller |
| 13 | **F17** ihtiyaç kadar modüler bakım | Stabil davranış üstünde küçük dilimler; tüm işi bekleten yeniden yazım yok |
| 14 | **R04/R05/R06/R07/R08/R10/R11/R13/R14/R15** koşullu rezerv | Yalnız karttaki tetik ve bağımlılıklar oluşursa planlanır. R11 pin eskimesi veya CVE tetiklediğinde; R13 F26 kullanımında tarama kontrolü ihtiyacı doğrulanınca açılır |
| 15 | **R09 wizard** en son | Aktif öncelikli işler sonrası, güncel UX verisiyle yeniden tasarım |

**Bağımsız AI ölçüm hattı:** F12a sıra 1 ile aynı planlama döneminde başlayabilir; API anahtarı gerektirmez. F12b uygun backend erişimiyle, F12c ise sonuçlar yeterliyse takip eder. Bu bir paralel ajan çalıştırma talimatı değil; geliştirme bağımlılığı tarifidir. Üretim varsayılanı ölçülmeden prompt/eşik değişmez; deterministik düzeltmeler bu hattı beklemez. R04/R05 ilgili F12 kapıları tamamlanmadan açılmaz.

**Her teslimatta:** yeni davranışın testleri aynı değişiklikle gelir. Mevcut davranışa dair gerçek tüketici doğrulaması tasarımı etkiliyorsa özelliğin öncesinde yapılır; bütün-kit dogfood RC yayın kapısında kalır. F01–F08 çözümleri bir sonraki stabil yayında ilgili regression ve tüketici doğrulamasını geçmelidir. Eski roadmap'teki “cache'den sonra hemen dep-scan” sırası artık geçerli değildir.

## Birlikte değerlendireceğimiz kararlar

İlk uygulama dilimi sıra 1–4: test kapısı ve kayıt/dağıtım güvenilirliği. Planlamada öncelikle baskın kullanıcıyı (tek geliştirici/ekip/çok repo), geliştirme kapasitesini ve eksik tarama durumunun hangi ortamlarda engelleyici olacağını netleştirelim. Mevcut fail-open davranışı geliştirme akışında korunabilir; daha sıkı CI profili ayrı seçilebilir. Başlangıç kullanıcı deneyimi mi yoksa büyük monorepo maliyeti mi daha acil, F14/F21 sırasını bu veri belirlemeli.

Bu tabloda kaba eforlar birbirinden bağımsız toplam bütçe değildir; ortak schema ve test işleri örtüşür. Seçilen paket için teknik tasarım sonrası yeniden tahmin yapılmalıdır.
