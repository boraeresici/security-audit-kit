# Security Audit Kit — Metodoloji ve Kullanılabilirlik Değerlendirmesi

Tarih: 10 Eylül 2026 · Baz: `main / 48fad91` (v1.17.0 + unreleased run lock)

Bu değerlendirme projenin kodunu taramak değil; **ürün olarak** güvenlik denetimi metodolojisi
çerçevesinde güvenlik ve development ekiplerince kullanılabilirliğini analiz etmektir.
Kod düzeyindeki tamamlayıcı bulgular SAST notlarından (Ek A) alınmıştır.

---

## 1. Ürün Kimliği ve Konumlandırma

Security audit kit, geleneksel güvenlik araçlarından (Snyk, Checkmarx, Veracode) farklı bir nişe
oturuyor:

| Geleneksel SAST/DAST | Security Audit Kit |
|---|---|
| SaaS veya sunucu gerektirir | Yerel, CI'dan bağımsız |
| Merkezi dashboard | Repo-içi, dağıtık |
| Aylık lisans maliyeti | MIT, ücretsiz |
| Uzman ekip yönetir | Developer self-service |
| Ayrı araç olarak çalışır | Git hook + AI ile entegre |

**Değerlendirme:** Konumlandırma net — "developer-first, offline, vendored security gate." SaaS
ürünleriyle rekabet etmiyor; onların yerine değil, **öncesinde** ve **yanında** çalışıyor. Bu,
küçük-orta ekipler ve bütçe kısıtlı organizasyonlar için güçlü bir değer önerisi. Ancak enterprise
güvenlik ekipleri için merkezi görünürlük eksikliği kabul engeli olabilir.

---

## 2. Metodoloji Kapsamı — Güvenlik Ekibi Perspektifi

### 2.1 Standart Güvenlik Denetim Çerçeveleriyle Eşleme

| Denetim Aşaması | Kit'in Karşılığı | Durum |
|---|---|---|
| **Varlık tespiti** (kod, bağımlılık, altyapı) | `doctor`, `sbom`, stack auto-detect | ✅ Yeterli |
| **Zafiyet taraması** (SAST, secret, deps, IaC, container) | `sast`, `secret`, `deps`, `iac`, `container`, `osv` | ✅ Kapsamlı |
| **Tedarik zinciri** | `guarddog`, `pkgcheck`, pin/digest mekanizması | ✅ Güçlü |
| **AI/LLM güvenliği** | `sec-ai-review` (OWASP LLM Top 10) | ✅ Öncü |
| **Tehdit modelleme** | `sec-threat-model` (STRIDE) | ✅ Var |
| **Derin analiz** (authz, iş mantığı) | `sec-sast-deep` | ✅ Özgün |
| **DAST / Runtime test** | Yok | ⛔ Bilinçli kapsam dışı |
| **API güvenliği testi** | Yok | ⛔ Eksik |
| **Uyumluluk eşleme** (PCI-DSS, SOC2, HIPAA) | Yok | ⛔ Eksik |
| **Risk önceliklendirme** (business context) | Severity normalization + AI triage | ⚠️ Kısmi |
| **SLA / remediation tracking** | Allowlist decay detection | ⚠️ Kısmi |
| **Merkezi raporlama** (çok repo) | Yok — tek repo HTML | ⛔ Eksik |
| **Penetrasyon testi** | Yok | ⛔ Bilinçli kapsam dışı |

**Sonuç:** Kit, **Identification + Detection** aşamalarında güçlü; **Governance, Compliance,
Response** aşamalarında bilinçli olarak eksik. Güvenlik ekibi bunu tek araç olarak değil, **ilk
savunma hattı** olarak konumlandırmalı.

### 2.2 Güvenlik Ekibinin İş Akışına Uygunluk

**Güçlü yönler:**

- **Triage yükünü azaltır:** AI katmanı (`sec-triage`) ham bulguları sınıflandırıyor; güvenlik
  ekibine yalnız `REAL` ve `UNCERTAIN` bulgular ulaşır. Büyük ekiplerde günde yüzlerce false
  positive ile uğraşan güvenlik mühendisleri için doğrudan değer üretir.

- **Kanıt kalitesi:** `evidence.json` → SARIF → HTML zinciri, bulgunun nerede, ne zaman, hangi
  araçla, hangi kararla tespit edildiğini gösterir. Güvenlik ekibi bu kanıtı auditör önünde
  kullanabilir.

- **Allowlist yönetimi:** `scan.sh allowlist` ile kabul edilmiş risklerin zamanla çürümesini
  tespit eder — governance açısından değerli.

- **Repo-içi kontrol:** Güvenlik ekibi kuralları (`semgrep-rules/`), allowlist'i ve exclusion'ı
  repo'da tutarak versiyonlar. "Gölgede güvenlik" yerine "şeffaf güvenlik" sağlar.

**Zayıf yönler:**

- **Merkezi görünürlük yok:** 10 repo'da kit kullanan bir organizasyon, hangi repo'da kaç açık
  bulgu olduğunu tek bakışla göremez. Güvenlik ekibi SARIF dosyalarını tek tek açmak veya Code
  Scanning panellerini repo bazında kontrol etmek zorunda.

- **Uyumluluk raporu yok:** PCI-DSS Requirement 6.5, SOC2 CC8.1 gibi kontrollere bulgu eşleme
  yapılamaz. Güvenlik ekibi denetim döneminde manuel eşleme tablosu hazırlamak zorunda.

- **Vulnerability aging:** Allowlist decay var ama "bu bulgu 90 gündür açık, SLA ihlali" uyarısı
  yok. Güvenlik ekibinin en çok ihtiyaç duyduğu metriklerden biri.

- **Risk context:** CVSS skoru var ama "bu CVE bu organizasyonda hangi varlığı etkiliyor" sorusu
  cevaplanamıyor. Security team risk kabul kararı verirken iş bağlamı ister.

### 2.3 Güvenlik Ekibi İçin Önerilen Geliştirmeler

| # | Geliştirme | Mevcut kart | Öncelik |
|---|---|---|---|
| 1 | Çok repo bulgu aggregation (SARIF merge + özet) | Backlog'da yok — **F26 önerilir** | P1 |
| 2 | Uyumluluk eşleme tablosu (CWE → PCI/SOC2/HIPAA) | Backlog'da yok — **R12 önerilir** | P2 |
| 3 | Bulgu yaşlandırma ve SLA uyarısı | F19'a eklenebilir | P2 |
| 4 | Executive summary çıktısı (tek sayfa, teknik olmayan özet) | F04'e eklenebilir | P2 |

---

## 3. Metodoloji Kapsamı — Development Ekibi Perspektifi

### 3.1 Developer Workflow Entegrasyonu

```
Developer İş Akışı:
  kod yaz → git add → [pre-commit: staged + deps] → git commit
     → [pre-push: verify + all] → git push → CI → PR → merge
```

| Aşama | Kit'in Sağladığı | Developer Deneyimi |
|---|---|---|
| **Kod yazma** | Yok (IDE entegrasyonu yok) | ⛔ Bulgu anında geri bildirim yok |
| **Staging** | `pre-commit` → staged secret + deps | ✅ Hızlı (sub-second secret scan) |
| **Commit** | Gate: secret varsa durdurur | ✅ Net ve hızlı |
| **Push** | `pre-push` → verify + all | ⚠️ İlk çalışmada Docker pull süresi |
| **PR** | CI: shellcheck + checksums + self-audit | ✅ Otomatik |
| **Triage** | AI skill'ler ile otomatik sınıflandırma | ✅ Developer'ı triajdan kurtarır |
| **Remediation** | AI önerileri (findings.md) | ⚠️ Öneri var, otomatik fix yok |

### 3.2 Developer Deneyimi Değerlendirmesi

**Güçlü yönler:**

- **Sıfır konfigürasyon başlangıç:** `bootstrap.sh` + `install.sh` ile 2 komutta kurulum.
  Developer'ın Docker, Python, veya npm bilmesi gerekmiyor — araçlar `uvx`/Docker ile otomatik
  çekiliyor.

- **CI bağımsızlığı:** Developer lokalde tam tarama yapabilir; CI faturası beklemez. Özellikle
  küçük startup'lar ve açık kaynak projeler için değerli.

- **Fail-fast kültürü:** `pre-commit` saniyeler içinde, `pre-push` dakikalar içinde sonuç verir.
  "CI'da 30 dakika sonra öğren" yerine "push anında öğren" deneyimi.

- **AI triage:** "Bu bulgu gerçek mi?" sorusunu AI cevaplar. Developer güvenlik uzmanı olmak
  zorunda kalmaz.

- **`doctor` komutu:** Araç zincirini, pin'leri ve algılanan stack'leri gösterir. "Neden
  çalışmıyor?" sorusunun cevabı tek komutta.

**Zayıf yönler:**

- **IDE entegrasyonu yok:** Developer kod yazarken zafiyeti göremez; yalnız commit/push anında
  öğrenir. Modern SAST araçları (Semgrep, SonarQube) IDE plugin'leri sunar.

- **Bash-only arayüz:** `scan.sh <command>` dışında CLI UX yok. `--help`, `--json`, `--format`
  gibi modern CLI ergonomisi eksik. Tab completion, interactive mode yok.

- **İlk çalışma sürtünmesi:** İlk `scan.sh all` çalışmasında Docker imajları indirilir — dakika
  sürebilir. Developer "kurulum tamamlandı" sanıp ilk taramada beklerse hayal kırıklığı yaşar.

- **Hata mesajları:** Bazı hata durumları `raw-*.log`'a düşüyor; developer'ın doğrudan gördüğü
  çıktı yetersiz kalabiliyor (F02, F04).

- **Remediation rehberliği eksik:** AI triage "bu gerçek, düzelt" diyor ama "nasıl düzeltilir"
  sorusu için kısa nota bırakıyor. Snyk'ın "fix PR" veya Dependabot'ın otomatik PR'ı gibi bir
  mekanizma yok.

### 3.3 Developer İçin Önerilen Geliştirmeler

| # | Geliştirme | Mevcut kart | Öncelik |
|---|---|---|---|
| 1 | `scan.sh help` — interaktif yardım | F14 | P1 |
| 2 | İlk çalışma öncesi araç indirme uyarısı | Backlog'da yok | P1 |
| 3 | Remediation önerisi zenginleştirme | R01 | P2 |
| 4 | VS Code / JetBrains extension | Backlog'da yok | P2 |
| 5 | `scan.sh --format json` — makine-okunabilir çıktı | F02 ile ilgili | P1 |

---

## 4. Metodolojik Güç ve Zayıflıklar

### 4.1 Güçlü Metodolojik Kararlar

**a) Deterministik Gate + Yargı Ayrımı**

Kit'in en özgün kararı. Geleneksel araçlar "bulgu var → durdur" veya "bulgu var → bildir"
mantığıyla çalışır. Kit, **deterministik tarama** (değişmeyen kurallar, sabit çıktı) ile **AI
yargısı** (bağlam gerektiren triyaj) katmanlarını ayırıyor.

- False positive oranını düşürür (AI, "bu test kodunda" diyebilir)
- Güvenlik ekibinin triyaj yükünü azaltır
- Developer'ı gereksiz durdurma ile yormaz

**b) Indeterminate Karar Modeli**

`exit code 3` — "taradım ama bakacak bir şey yoktu." Sessiz `pass`'ten çok daha dürüst. v1.17.0'daki
`py-deps` hatası (boş venv = yanlış temiz) bu yaklaşımın neden gerekli olduğunu kanıtlıyor.

**c) Tedarik Zinciri Bilinci**

Tool pinleme (digest), CHECKSUMS, `scan.sh verify`, pre-push integrity, tag-repair guard. Bir
güvenlik aracının kendi bütünlüğünü korumaması ironik ve tehlikeli olurdu; kit bunu ciddiye alıyor.

**d) Fail-Open Tasarımı (Bilinçli)**

Eksik araç → boyut atlanır, tarama durmaz. Kit'in felsefesi açık: "insanların routing around
yaptığı bir gate, korumayan bir gate'dir."

### 4.2 Metodolojik Riskler ve Boşluklar

**a) AI Yargısına Bağımlılık**

`sec-triage`'ın varsayılan kararı FP (false positive) olması durumunda — `sec-triage.skill.md:69`'da
bu eğilim belirtilmiş — gerçek bir bulgu FP olarak işaretlenip allowlist'e girebilir.

- **Risk:** Developer `sec-triage` çalıştırdı → AI "FP" dedi → allowlist'e eklendi → güvenlik
  ekibi hiç görmedi.
- **Mitigasyon:** `UNCERTAIN` kategorisi ve allowlist decay detection (`scan.sh allowlist`) kısmen
  koruyor. F12 kalibrasyon çalışması tamamlanana kadar bu risk açık.

**b) Kapsam Yanılsaması**

`scan.sh all` komutu OSV, GuardDog, zizmor ve SBOM'u **içermiyor**. Developer "tam tarama yaptım"
sanabilir ama aslında:
- Multi-ecosystem dep CVE (osv) → opt-in
- Malicious deps (guarddog) → opt-in
- GitHub Actions güvenliği (zizmor) → opt-in

F14'teki "kapsam özeti" önerisi bunu çözecek.

**c) Tek Repo Sınırı**

Kit tek repo'nun güvenliğini tarar. Organizasyon düzeyinde güvenlik posture göstermez. Enterprise
güvenlik ekibi "50 repo var, hangisi en riskli?" sorusunu kit ile cevaplayamaz.

**d) DAST Yokluğu**

Bilinçli bir karar. OWASP Testing Guide'ın büyük bölümü runtime test gerektirir. Kit, penetration
test'in yerine değil, **öncesindeki filtre** olarak konumlandırılmalı.

**e) Python Araçlarının Bütünlük Açığı**

Docker araçları digest ile korunurken, Python araçları (semgrep, checkov, pip-audit, guarddog,
zizmor) PyPI'dan versiyon numarasıyla çekiliyor — hash doğrulaması yok. PyPI compromise senaryosunda
Docker araçları bağışık, Python araçları değil. R06 ve R11 kartları bu açığı ele alıyor.

**f) Config Dosyasının Çalıştırılabilir Doğası**

`.security-audit.conf` shell `source` ile yükleniyor — düz veri dosyası değil, çalıştırılabilir
kod. Repo'ya yazma erişimi olan biri config'e keyfi komut ekleyebilir. F11 tehdit modeli ve F24
config doğrulama kartları bu riski ele alıyor.

---

## 5. Hedef Kitle Uygunluk Matrisi

| Kullanıcı Profili | Uygunluk | Neden |
|---|---|---|
| **Solo developer / indie hacker** | ⭐⭐⭐⭐⭐ | Tam uygun — düşük maliyet, sıfır altyapı, self-service |
| **Küçük startup (2-10 dev)** | ⭐⭐⭐⭐ | Çok uygun — CI maliyeti yok, hızlı kurulum |
| **Orta ölçekli ekip (10-50 dev)** | ⭐⭐⭐ | Uygun ama merkezi rapor ve uyumluluk eksikliği hissedilir |
| **Enterprise güvenlik ekibi** | ⭐⭐ | İlk savunma hattı olarak değerli; governance katmanı eksik |
| **Açık kaynak projesi** | ⭐⭐⭐⭐⭐ | Tam uygun — ücretsiz, yerel, Code Scanning entegrasyonu |
| **Regulated industry** (fintech, health) | ⭐⭐ | Uygun ama PCI-DSS/HIPAA mapping olmadan yeterli değil |
| **Security consultant / pentester** | ⭐⭐⭐ | Hızlı ilk değerlendirme; derin analiz için DAST gerekli |

---

## 6. Sonuç ve Öneriler

### Ürün Olarak Güçlü Yönler

1. **Net konumlandırma** — SaaS rakipleriyle değil, onların önünde çalışıyor
2. **Deterministik + AI ayrımı** — Sektörde özgün metodolojik yaklaşım
3. **Tedarik zinciri bilinci** — Kendi bütünlüğünü koruyan güvenlik aracı
4. **Developer-first tasarım** — Git hook, sıfır config, hızlı feedback
5. **Indeterminate model** — Sessiz pass yerine dürüst "bakamadım"

### Ürün Olarak Geliştirilmesi Gerekenler

1. **Merkezi görünürlük** (P1) — Çok repo aggregation olmadan enterprise satışı zor
2. **IDE entegrasyonu** (P2) — Commit öncesi feedback loop modern beklenti
3. **Uyumluluk eşleme** (P2) — Regulated industry için olmazsa olmaz
4. **Kapsam iletişimi** (P1, F14) — "all" komutunun neyi kapsamadığı net söylenmeli
5. **AI kalibrasyon** (P1, F12) — FP default riski ölçülmeden ürün kararlı sayılmaz

### Metodoloji Kapsamında Eklenmesi Önerilen Kartlar

Mevcut F23–F25 + R11'e ek olarak, metodoloji değerlendirmesinden iki yeni kart önerilir:

| ID | İş | Tür | Öncelik | Neden |
|---|---|---|---|---|
| **F26** | Multi-repo finding aggregation | Geliştirme | P1 | Güvenlik ekibinin temel görünürlük ihtiyacı; tek repo sınırı enterprise adoption engeli |
| **R12** | Uyumluluk çerçeve eşleme (CWE → PCI/SOC2/HIPAA) | Koşullu | P2 | Regulated industry adoption için gerekli; somut tüketici talebi olmadan açılmaz |

---

## Ek A — SAST Bulguları (Kod Düzeyi Tamamlayıcı)

Bu bulgular 10 Eylül 2026'da gerçekleştirilen statik kod analizinden alınmıştır. Metodoloji
değerlendirmesindeki riskleri doğrulayan bulgular öncelenmiştir.

### A1 — Config dosyasının çalıştırılabilir doğası (HIGH)

**Dosya:** `scan.sh:52` — `. "$CONF"`

`.security-audit.conf` doğrudan shell'e source ediliyor. Dosya keyfi komut içerebilir
(`curl | bash`, `eval` vb.). Repo'ya yazma erişimi olan saldırgan her developer ve CI
runner'da kod çalıştırabilir.

**İlgili kart:** F11 (tehdit modeli) + F24 (config doğrulama). Bu bulgu her iki kartın da
önceliğini doğruluyor.

### A2 — Docker container'ların read-write repo mount'u (MEDIUM)

**Dosya:** `scan.sh:304, 381, 391, 451, 459, 495` — `-v "$ROOT:/repo"`

Altı Docker container çağrısının tümü repo'yu okuma-yazma olarak mount ediyor. Üçüncü parti
container imajı (compromise durumunda) repo dosyalarını değiştirebilir. `:ro` mount yeterli
olacak çoğu boyut için uygulanmadığı görülüyor.

**İlgili kart:** F11 (tehdit modeli).

### A3 — Python araçlarında hash doğrulaması yokluğu (MEDIUM)

**Dosya:** `scan.sh:204-211` — `pyrun` fonksiyonu

Python araçları versiyon numarasıyla PyPI'dan çekiliyor; Docker araçları immutable digest ile
korunurken Python araçları değil. PyPI compromise senaryosunda `semgrep==1.166.0` zararlı paketle
değiştirilebilir.

**İlgili kart:** R06 (Python hash-pin kararı) + R11 (pin güncelleme otomasyonu).

### A4 — Lock reclaim TOCTOU penceresi (MEDIUM)

**Dosya:** `scan.sh:1098-1108`

Stale lock reclaim'de PID ölümü kontrolü ile `rm -rf` arasında TOCTOU penceresi var. PID geri
dönüşümü senaryosunda iki süreç aynı kilidi sahiplenebilir.

**İlgili kart:** F05 (kilit yaşam döngüsü). Bu bulgu, 8 Eylül değerlendirmesindeki F05 tespitini
bağımsız olarak doğruluyor.

### A5 — Guarddog argüman enjeksiyonu (MEDIUM)

**Dosya:** `scan.sh:567-569` — `$gargs` word-split

Paket adı ve sürümü `$gargs` içine gömülüp word-split ile guarddog'a geçiriliyor. Boşluklu veya
meta karakterli paket adı ek argüman üretebilir.

**İlgili kart:** F18 (platform/yol matrisi). Boşluklu yol/argüman güvenliği kapsamında ele alınmalı.

### A6 — `bootstrap.sh --expect` prefix match (LOW)

**Dosya:** `bootstrap.sh:97-99` — `case "$SHA" in "$EXPECT_SHA"*)`

SHA karşılaştırması prefix match kullanıyor. Kısa prefix ile collision mümkün. Tam 40 karakter SHA
kullanıldığında risk yok; ancak kullanım kolaylığı için kısa prefix kabul ediliyorsa güvenlik
zayıflar.

---

## Ek B — Backlog Eşleme Tablosu

Bu değerlendirmeden çıkan bulguların mevcut backlog kartlarıyla eşlemesi:

| Metodoloji Bulgusu | Backlog Kartı | Durum |
|---|---|---|
| Kapsam yanılsaması | **F14** — Kapsam özeti | Backlog'da var, öncelik doğru |
| AI yargı bağımlılığı | **F12** — Kalibrasyon | Backlog'da var, öncelik doğru |
| Config çalıştırılabilir | **F11 + F24** | F11 var, F24 bu değerlendirme ile eklendi |
| Merkezi görünürlük eksik | **F26 önerilir** | Backlog'da yok — yeni kart önerisi |
| Uyumluluk eşleme eksik | **R12 önerilir** | Backlog'da yok — koşullu kart önerisi |
| IDE entegrasyonu eksik | — | Backlog'da yok — P2 gelecek planı |
| Python bütünlük açığı | **R06 + R11** | Backlog'da var, SAST ile doğrulandı |
| Docker read-write mount | **F11** | Backlog'da var, SAST ile doğrulandı |
| Lock TOCTOU | **F05** | Backlog'da var, SAST ile doğrulandı |
| Remediation rehberliği | **R01** | Backlog'da var, kapsam kararı bekliyor |
| İlk çalışma sürtünmesi | — | Backlog'da yok — UX iyileştirmesi |
| Bulgu yaşlandırma / SLA | **F19**'a eklenebilir | Backlog'da kısmi var |
| Executive summary | **F04**'e eklenebilir | Backlog'da kısmi var |
