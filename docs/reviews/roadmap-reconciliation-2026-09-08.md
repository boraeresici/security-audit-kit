# Roadmap değerlendirmesi ve birleşik iş sırası

Tarih: 8 Eylül 2026 · Baz: yerel `main / 48fad91`.

Güncel uygulama sırası ve kabul kriterleri [birleşik iş listesinde](application-backlog-2026-09-08.md). Bu belge, eski roadmap maddelerinin neden kapandığını, birleştiğini veya ertelendiğini açıklar. İncelenen kaynaklar: `ROADMAP.local.md`, `IMPLEMENTATION-PLAN.local.md`, `AI-JUDGMENT-DESIGN.local.md`, `WIZARD-DESIGN.local.md`, CHANGELOG ve ilgili uygulama kodu. Yerel kaynakların tarihi beyanları güncel ürün/sağlayıcı ölçümü sayılmadı; dış araç lisansları ve yetenekleri yeniden araştırılmadı.

## Temel karar

Eski sıradaki “hemen cache, ardından remediation ve ağır reachability” akışını güncelliyoruz. Önce hatalı tarama kayıtları ve paket-cache politika sorunu giderilecek. Cache ancak doğru sonucu sakladığını kanıtlayabildiğimizde değerli. Buna karşılık remediation'ın küçük kapsam kararı ve L1d'nin anahtarsız hazırlığı cache'i beklemek zorunda değil.

İlk değerlendirmedeki F21 de iki teslimata ayrıldı: **F21a boyut cache'i → F21b monorepo kapsamı**. Monorepo teslimatı cache'in çıkmasını bekletmeyecek. F12 ise **tanım/ölçüm altyapısı → backend ölçümü → ürün karar değişikliği** olarak ayrıldı. 0.7 eşiğini değiştirmek için mevcut tarihsel sonuçlar yeterli değil.

## Mevcut veya kapanmış maddeler — tekrar geliştirme yok

| Eski referans | Yerelde görülen durum / kanıt | Yeni karar |
|---|---|---|
| T1.1–T1.4; C1; plan #4; Phase A | Kanıt eşiği, exclusion, reachability, 3 aşamalı inceleme ve tutarlılık kontrolü `skills/` içinde mevcut | Temel tamam; kalibrasyon/UNCERTAIN açığı F12 |
| T2.1; R1/R2; plan #15 | AI yüzeyleri, threat model, incomplete-fix ve availability soruları mevcut | Yeniden ekleme yok; kalite ölçümü F12 kapsamı |
| T2.2 offline OSV→SQLite | Roadmap zaten özel DB senkronunu bırakmış; `scan_osv` mevcut | Kapalı; OSV'nin varlığını bütün akışın ağsızlığıyla eşitleme, F13 |
| T2.2 / #8 judgment yarısı | `sec-triage` doğrudan/transitive ve parent-range sorularını soruyor | Mevcut; yalnız compute ihtiyacı R01 |
| T2.3 KEV/EPSS | Skill ve CHANGELOG isteğe bağlı canlı sorguyu anlatıyor | Mevcut, fakat roadmap'teki “offline snapshots, pinned” ilk tasarımı gerçekleşmiş sayma; F13'te düzelt |
| T3.1 / plan #5 a+b+c | `lib/evidence.py`, `lib/kit_sarif.py`, `lib/report_html.py` ve şema mevcut | Üç çıktı tamam; doğruluk F01–F04, kapsam F16; JSONL/resume ayrı kalan ihtiyaç |
| T3.3 / Incoming sec-audit | Orchestrator mevcut | Kapalı |
| Tier S Layer 0/2 + non-crypto + CI pinleri | bootstrap pin kontrolü, CHECKSUMS/verify ve pinli workflow'lar mevcut | Temel tamam; release boşlukları F07/F08, tehdit modeli F11 |
| Incoming OSV; A1/A2; plan #1/#2 | `scan_osv`, `scan_guarddog`, `scan_zizmor` mevcut | Eski boş checkbox'ları yeni iş sayma |
| L1/C3; L1b/#10; L1c | Harness, matrix config, provider filtreleme/skor gruplama mevcut; YAML'da 31 dev + 36 holdout = 67 vaka başlığı | Altyapı tamam; korpus/model kalite iddiası değil. Kalibrasyon ve yeni kapsam F12 |
| plan #12 suppression fan-out | Skill eşleme tablosu ve yeniden tarama zorunluluğu mevcut | Mekanizma tamam; gerçek trivy/uv.lock doğrulaması F16a; alias/karar yaşam döngüsü F19 |
| plan #13 allowlist drift | `scan_allowlist` ve CHANGELOG'da mevcut | Temel tamam; exact-id ve mevcut dosya sınırlamaları F19 |
| plan #14 local rules | Discovery, yerel kuralların eklenmesi ve `rules-test` mevcut | Tamam; tüketiciye özel kuralları kite ekleme |
| plan #11 stack-auto field verify | Önceki plan uygun gerçek tüketici bulunmadığından e2e ile kapatmış | Kapalı tut; uygun tüketici çıkarsa RC turuna ekle, bağımsız engelleyici iş değil |
| R5.1 install-time hook | `pkgcheck`, parser, PreToolUse hook mevcut | Özellik tamam; cache politika hatası F06 |
| R5.2 slice A | Kilit kodu main'de; CHANGELOG `Unreleased` altında | “Henüz geliştirilmedi” değil; F01/F05 düzeltmesi gerekiyor. Remote yayın doğrulanmadı |
| #9 WSL2 | Doküman/platform tespiti mevcut; gerçek WSL2 doğrulaması yok | Kısmi; kalan F18, yeniden platform dokümanı projesi açma |

## Açık roadmap maddelerinin değerlendirmesi

| Eski madde | Değer / maliyet değerlendirmesi | Yeni karşılık / açılma koşulu |
|---|---|---|
| R5.2 slice B | Tekrarlı tarama maliyetini azaltır; eksik invalidation yanlış temiz sonucu kalıcılaştırır | F20 ölçümü ardından F21a; kit/pin/config/rule/allowlist/advisory güncelliği anahtara dahil; kanıtlanamayan boyut cache dışı |
| R5.4 affected subtree | Büyük monorepo'da yararlı; shared lockfile ve ortak bileşenler kapsam kaçırabilir | F21b; F21a sonrası, gerçek monorepo darboğazı varsa |
| L1d calibration | AI katmanının mevcut kalite iddialarını anlamlandırmak için yüksek değer | F12a anahtarsız tanım/rubric/fixture → F12b aynı split ölçüm → F12c ürün değişikliği; en erken bağımsız hat |
| #8 compute yarısı | Kullanıcıya uygulanabilir çözüm sağlayabilir; tüm ekosistemler için resolver yazmak pahalı | R01 önce K eforlu kapsam kararı. Skill'in mevcut read-only komutları yeterliyse yeni scanner kodu açma |
| #7/A3 Python-JS reachability | Go dilimi mevcut. Kalan ağır kurulum ve dakikalar sürebilen çalışma getiriyor | R03; yüksek triyaj yükü gösteren tüketici + F21a + F16 sonrası sınırlı pilot |
| R5.3 skills-only plugin | Vendor almadan yargı katmanını denemeyi kolaylaştırır; tarayıcı yoluna bağımlılıklar çözülmeli | R02; F10/F11/F14 sonrası. Önce manifest/izin/kök sözleşmesi, sonra dağıtım. Phase B önkoşul değil |
| T3.2/#6 ve B.1 extraction | Roadmap'in kendi ölçümü sürekli token tasarrufu gerekçesini çürütmüş | R10 ertelendi; gerçek bakım sorunu veya R04 ihtiyacı olmadan bağımsız yeniden düzenleme yok |
| T3.1 JSONL zinciri; Phase A SQLite/checkpoint | Raporlar mevcut ama dayanıklı olay geçmişi/resume başka yetenekler | Kimlik/karar modeli F19'a bağlı koşullu dilim; kesilen uzun koşum maliyeti gösterilmeden JSONL ve DB birlikte kurma |
| T3.4 prove-it PoC | İnceleme kanıtını güçlendirebilir; üretim maliyeti ve güvenlik sınırı daha yüksek | R05, F12/F19 sonrası ihtiyaca bağlı; yalnız üretim, otomatik yürütme yok |
| L2 triage-lite + Phase B | Offline/non-Claude ihtiyacına cevap; araç döngüsü ve kalite sorumluluğu yeni bakım yükü | R04 tek program, iki ardışık dilim: ölçülmüş triage-lite pilotu; gerekirse tam agent loop |
| L3 güçlü modelde deep | Bir özellik teslimatı değil, kalite kısıtı | R04 kabul kriteri. Küçük modelin yeterli olduğu veya büyük modelin yetersiz olduğu tarihsel varsayımlar ölçüm yerine kullanılmaz |
| Python tool hash-pin | Ek bütünlük sağlar; araç başına bağımlılık/platform kilitleri bakım gerektirir | R06; F11 sonrası önce bakım maliyeti kararı, runtime modelini sessizce değiştirme |
| Tier S Layer 3 cosign/Rekor | Bağımsız yayıncı kimliği ihtiyacına cevap | R07; tüketici/adoption talebi ve F07 sonrası; mevcut hash kontrolünün yerine değil yanına |
| A4/A5 scorecard/conftest/modelscan | Genel kullanıcı için gereklilik gösterilmemiş | R08 koşullu; somut statik kapsam açığı, uyumlu dağıtım ve lisans doğrulaması varsa |
| CLI wizard | Tasarım/mock hazır; yeni runtime değeri henüz ölçülmemiş | R09; önceki “en son” tercihi korunur, F14 kısa yardım bunun yerine geçen bir wizard değildir |
| MCP girişleri / declarative manifest / SQLite | Entegrasyon ya da orkestrasyon acısı varsa değerli | MCP R04 veya F16 için gerçek veri tüketicisi gerektirir; manifest/resume ölçülmeden ayrı ana iş açılmaz |

## Aktif sıraya alınmayanlar

Nuclei erken listede “maybe” olsa da sonraki Round 4 DAST kararında kapsam dışı bırakılmış. Yeni talep olmadan yeniden açılmıyor. R3 fuzzing/differential testing, runtime monitoring, host/DB backup araçları, CSPM, otonom exploit, dış agent multiplexer'ları ve mevcut tarayıcıları yineleyen araçlar kit işi değil. İhtiyaç tüketici projede ele alınır; örnek fuzz scaffold bile ayrı talep gerektirir.

Güncel sıralama dış paket seçimi veya kurulum onayı değildir. Plugin/provider işi uygulanacağı zaman ilgili host sözleşmeleri ve araçların o günkü özellik/lisansları yeniden doğrulanmalıdır. Şimdi yapılan, mevcut yerel tasarımların değer ve bağımlılık değerlendirmesidir.

## Eski sıraya göre değişenler

1. Kilit dilimi “bitti, cache'e geç” olmaktan çıktı; önce F01/F05 doğruluk düzeltmeleri.
2. F09 test kapısı en öne geldi; F07/F08 bir sonraki stabil yayın öncesi kapı oldu.
3. Remediation kapsam kararı R01 ağır cache/reachability işinden önceye alındı; küçük kararı büyük uygulamayla karıştırmıyoruz.
4. Kalibrasyon F12a anahtara bağlı olmadan başlayabilir. Ölçüm F12b ve ürün değişikliği F12c ayrı kapılar; 0.7 eşiği şimdilik korunuyor.
5. Plugin R02, ağır reachability R03'ten önceki genişletme adayı; kalıcı tercih değil, onboarding ve triyaj verisiyle açılan işler.
6. F21a cache ve F21b monorepo ayrı teslim edilir. JSONL/resume ise F19'a koşullu bağlandı.
7. Wizard son planlı özellik; yerel model, tam provider runner, yeni tarayıcı ve signing otomatik sprint taahhüdü olmadı.

## Doğrulama ve bakım

Bu turda yalnız planlama belgeleri güncellendi; uygulama/prompt değiştirilmedi, test veya LLM eval tekrar koşulmadı. Mevcut koddaki fonksiyonlar, CHANGELOG, eval provider gruplama/filtreleme ve korpus başlık sayıları karşılaştırıldı. Önceki incelemenin 93/0 çevrimdışı test sonucu yeni koşum diye sunulmaz.

Yerel roadmap/plan dosyaları gitignored kalır; kalıcı paylaşılabilir kaynak `docs/reviews/` altındaki birleşik iş listesi ve bu eşleme belgesidir. Remote release/issue durumu bu turda sorgulanmadı. Eski araştırma metinleri tarihçe olarak korunur; çelişkide güncel iş sırası geçerlidir.
