# Security Audit Kit — çok rollü uygulama değerlendirmesi

Tarih: 8 Eylül 2026 · İncelenen yerel commit: `48fad91` · Dal: `main`

Bu değerlendirme uygulama kodunu değiştirmeden hazırlanmıştır. İşlerin tamamı öneridir; planlama ve uygulama onayı verilmiş sayılmaz. Önceliklendirilmiş karşılığı: [iş listesi](application-backlog-2026-09-08.md).

## Yönetici değerlendirmesi

Ürünün güçlü çekirdeği, farklı güvenlik tarayıcılarını repo içine taşınabilen tek bir akışta birleştirmesi ve tarama ile AI yargısını ayırmasıdır. Sürüm/digest pinleme, bütünlük manifesti, günlük ham kayıt, SARIF, normalize kanıt ve çevrimdışı HTML rapor mevcut. Yeni tarayıcı eklemekten önce **çıktının hangi çalıştırmaya ait olduğunu ve gerçekten neyin tarandığını güvenilir biçimde göstermek** daha yüksek değer taşıyor.

En önemli sonuç: mevcut çevrimdışı e2e testleri geçmesine rağmen kilit zaman aşımı, eksik tarayıcı ve eski SARIF bileşimi yanlış bir tarama kaydı üretebiliyor. Bunlar üretimde istismar gösterimi yapılmış güvenlik açıkları olarak değil, yerel olarak doğrulanmış doğruluk ve güvenilirlik hataları olarak sınıflandırılmıştır.

Önerilen sıra: kayıt güvenilirliği → otomatik kalite kapıları → kurulum ve sonuç anlaşılabilirliği → ölçümle gerekçelendirilmiş performans ve kapsam geliştirmeleri.

## Kapsam ve yöntem

İncelenen yüzeyler: `scan.sh`, `bootstrap.sh`, `install.sh`, üç hook, `lib/` içindeki dört Python modülü, beş `sec-*` talimatı, e2e/eval yapısı, CI ve release akışı, İngilizce/Türkçe README, güvenlik politikası, evidence şeması, landing HTML/build/headers ve yerel yol haritaları.

Roller ayrı değerlendirme perspektifleridir; bağımsız insan/ajan incelemeleri yapılmış olduğu iddia edilmez.

- **D — Deneyle doğrulandı:** geçici Git reposunda sentetik veriyle davranış yeniden üretildi.
- **K — Kod/doküman kanıtı:** uygulama yolu veya açık doküman sınırlaması incelendi; etki uçtan uca ölçülmedi.
- **Ö — Öneri:** kullanıcı/performans ölçümü ile doğrulanması gereken ürün fırsatı.

Canlı servise saldırı, dış tarayıcı indirme/çalıştırma, ücretli LLM değerlendirmesi, gerçek WSL2 testi, kullanıcı görüşmesi ve tarayıcıda görsel/erişilebilirlik testi yapılmadı. Rakiplerin güncel özellikleri ve pinli araçların güncel CVE durumları bu çalışmanın kapsamında doğrulanmadı. Tanıtım sayfası için sonuçlar kaynak kodu incelemesidir.

## Doğrulama sonuçları

| Kontrol | Sonuç | Yorum |
|---|---|---|
| Başlangıç çalışma ağacı | Temiz | Var olan kullanıcı değişikliği üzerine yazılmadı |
| Shell sözdizimi | Seçilen dokuz script `bash -n` kontrolünü geçti | ShellCheck veya davranış testi yerine geçmez |
| Python sözdizimi | `lib/` içindeki dört modül AST parse kontrolünü geçti | Runtime/adaptör uyumu testi yerine geçmez |
| `bash scan.sh verify` | 69 dosya manifest ile eşleşti | Başlangıçtaki takipli dosyaların bütünlüğü |
| Çevrimdışı e2e | **93 geçti, 0 başarısız; 10 bölüm atlandı** | `PATH=/usr/bin:/bin:/usr/sbin:/sbin bash tests/e2e.sh`; dış tarayıcılar ve Node bu PATH'te yoktu |
| Kilit doluyken ikinci tarama | Ortak `summary.json` değişti | F01; `SCAN_LOCK_WAIT=0`, canlı PID'li kilit |
| Docker olmadan secret | Çıkış 0, boyut `pass` | F02; tarama gerçekte atlandı |
| Eski SARIF + atlanan secret | Önceki sentetik bulgu yeni evidence içine alındı; uyarı yok | F03 |
| Çıkış kodu bulunmayan evidence → HTML | `clean (exit 0)` yazdı | F04 |

### Tekrar üretme tarifi

Geçici bir Git reposunda `docs/security/scan-findings/sarif/gitleaks.sarif` içine tek sentetik sonuç ve `summary.json` içine ayırt edilebilir bir işaret koy. `.git/security-audit-cache/scan.lock/owner` dosyasına halen yaşayan bir sürecin `pid=<PID> date=now cmd=fixture` bilgisini yaz. Bu repo içinden, kitin mutlak yolunu kullanarak `PATH=/usr/bin:/bin:/usr/sbin:/sbin SCAN_LOCK_WAIT=0 SARIF=1 /bin/bash <kit>/scan.sh secret` çalıştır. Docker'ın bu PATH'te bulunmadığını doğrula.

Gözlenen sonuç: “SEPARATE log” mesajına rağmen ortak özet üzerine yazıldı; `secret` durumu `pass` oldu; evidence bir eski bulgu içerdi ve `warnings=[]` çıktı. Bu deney kilit zaman aşımı yolunu deterministik olarak sınar; iki gerçek tarayıcının aynı anda çalıştığı yük testi değildir.

F04 için `schema=security-audit-kit/evidence@1`, `scan={}`, `counts={total:0}`, `findings=[]` içeren JSON, `lib/report_html.py` ile üretildi; çıktı `clean (exit 0)` içerdi.

## Rollere göre değerlendirme

### 1. Ürün yöneticisi

**Güçlü:** Yerel ve repo kapsamlı kullanım, düşük altyapı ihtiyacı, deterministik kontrol ile yargı ayrımı net bir ürün kimliği oluşturuyor. OSV/GuardDog/zizmor gibi ek boyutların isteğe bağlı olması maliyeti kontrol ediyor.

**Gelişim:** `all` komutu OSV, GuardDog, zizmor ve SBOM'u kapsamıyor (`scan.sh:1137`). Bu bilinçli ve belgelenmiş; ancak ilk kullanıcının “tam tarama” beklentisiyle karışabilir. Çalıştırmadan önce/sonra etkin, uygulanamaz ve isteğe bağlı boyutları gösteren kapsam özeti ve kullanım profilleri önerilir (F14).

“Nothing leaves your machine” / “network only in opt-in dimensions” gibi landing ifadeleri, standart akışın `uvx`, registry kuralları, dependency audit ve AI servisi kullanabilmesiyle uyumlu bir veri akışı açıklaması gerektiriyor. Yerel çalıştırma, ağsızlık ve verinin dış servise gönderilmesi ayrı kavramlar olarak anlatılmalı (F13). Bu inceleme gerçek ağ paketlerini ölçmedi.

Ürün başarısı yeni araç sayısıyla değil; ilk işe yarar rapora ulaşma süresi, eksik kapsam oranı, tarama gecikmesi ve kapanan gerçek bulgu oranıyla ölçülmeli. Bunlar varsayılan telemetri olmadan yerel metriklerle başlayabilir (F20).

### 2. Geliştirici deneyimi / UX

**Güçlü:** `doctor`, sıfır konfigürasyon, çift dil README, `--skills-only`, kopyalanabilir kurulum komutları ve framework bağımsız rapor iyi başlangıç noktaları.

**Gelişim:** Kurulum mevcut `core.hooksPath` değerini doğrudan değiştiriyor (`install.sh:45`); README alternatifleri anlatsa da kurulum mevcut hook sahibini tespit edip somut seçenek göstermiyor. Mevcut davranışı koruyan kurulum planı, yedek ve geri alma gerekli (F10).

`scan.sh` komut yardımını ve sonuç özetini geliştirmek, uzun README'yi başlangıç/ileri kullanım/referans olarak ayırmak ilk kullanım sürtünmesini azaltır (F14). `scan_report()` ve `scan_evidence()` eksik girdide ya da bazı üretim hatalarında 0 döndüğü için otomasyon dosyanın gerçekten üretildiğini ayrıca kontrol etmek zorunda (F04).

Landing kopyala düğmesinde clipboard reddi için hata yolu bulunmuyor; animasyonlu görünürlük `IntersectionObserver` ve JS'ye bağlı (`landing/index.html:543`). JS kapalı kullanım, klavye odağı, kopyalama hatası, ekran okuyucu bildirimi ve mobil taşma tarayıcıda sınanmalı (F15). Azaltılmış hareket desteği zaten var; yeniden yapılacak özellik sayılmamalı.

### 3. Yazılım mimarı / backend

**Güçlü:** Python yardımcıları stdlib ile çalışıyor; evidence ortak model olarak rapor ve SARIF üreticilerini ayrıştırıyor. Başlıca davranışlar fonksiyonlara ayrılmış.

**F01 — D, yüksek:** `scan.sh:1193` kilit alınamayınca yalnız `LOG` yolunu değiştiriyor. `SUMMARY`, `SARIF_DIR`, `EVIDENCE` ve HTML yolu ortak kalıyor; `scan.sh:1230` civarındaki atomik rename ortak özeti yine değiştiriyor. Atomik dosya yazımı, farklı çalıştırmaların aynı kaydı sahiplenmesini engellemiyor. Her çalıştırma ayrı dizin kullanmalı; ortak “son tamamlanan çalışma” işaretçisi yalnız uygun kilitle güncellenmeli.

**F02 — D/K, yüksek:** `scan_secret()` ve eksik toolchain yolları 0 döndürüyor (`scan.sh:375`, `396`); özet üretimi 0'ı `pass` yapıyor. Python manifest yokluğu için mevcut `indeterminate` yaklaşımı tüm boyutlara taşınmalı. Tarama sonucu ve engelleme politikası farklı alanlar olmalı; geliştirmeyi engellemeden eksik kapsam doğru kaydedilebilir.

**F03 — D, yüksek:** `lib/evidence.py:392` boyut adına göre dosya seçiyor; dosyanın bu çalıştırmada üretilip üretilmediğini doğrulamıyor. Aynı boyut atlanınca eski SARIF geçerli sayılıyor. Çalıştırma kimliği, commit/kapsam bilgisi ve o çalıştırmanın artifact manifesti gerekli.

**F05 — K:** `scan_lock_acquire()` canlı PID olsa bile yaş sınırı aşılmış kilidi silebiliyor; `scan_lock_release()` sahiplik token'ı doğrulamadan dizini siliyor (`scan.sh:1090`). Uzun tarama ve PID yeniden kullanım senaryoları, sahiplik token'ı/heartbeat ve yarış testleriyle ele alınmalı.

**F17 — Ö:** `scan.sh` tarayıcı adaptörleri, keşif, kilit, allowlist, cache ve JSON üretimini tek dosyada taşıyor. Önce davranış sözleşmelerini testlerle sabitleyip küçük modüllere ayırmak uygun; tüm sistemi yeniden yazmak için kanıt yok.

### 4. Güvenlik mühendisi / tedarik zinciri

**Güçlü:** İmaj digest'leri, pin doğrulama, tag-repoint kontrolü, manifest, redaction ve build-script riskinin açık ele alınması değerli. Bu kontrollerin varlığı korunmalı.

**F06 — K, yüksek:** `pkgcheck_one()` cache anahtarında ekosistem, paket, sürüm ve GuardDog sürümü bulunuyor; `PKGCHECK_BLOCK_EXTRA`/`PKGCHECK_REPORT_EXTRA` bulunmuyor (`scan.sh:551`). Cache'den ham analiz yerine önceki karar okunuyor. Politika sertleştiğinde önceki kararın tekrar kullanılması mümkün. Ham analiz cache'lenip güncel politika uygulanmalı veya politika digest'i anahtara eklenmeli. Tam sürümlerde süresiz cache için de açık yenileme/geçersizleştirme kuralı tanımlanmalı.

**F07 — K, yüksek:** `scripts/release.sh:60` civarında `gh` yokluğu, check-run bulunamaması ve eksik zorunlu kontroller uyarıyla geçiliyor; `preflight` başarısız fetch sonrası devam edebiliyor. Release belgesindeki zorunlu doğrulama ile otomasyonun davranışı ayrışıyor. Stabil yayın için doğrulanamayan kontrol açık başarısızlık olmalı; acil istisna gerekiyorsa ayrıca kayıtlı ve bilinçli olmalı.

**F08 — K:** `bootstrap.sh:60` güncelleme adayını bütün sürüm etiketlerini sıralayarak seçiyor; `-rc.N` ayıklanmıyor. Stabil kanalın RC önerme ihtimali yerel tag fixture'ıyla test edilmeli. `RELEASING.md` stabil/RC ayrımıyla uyumlu kanal seçimi gerekir.

**F11 — K:** `.security-audit.conf` shell olarak source ediliyor (`scan.sh:48`); bu normal bir konfigürasyon veri dosyası değil, çalıştırılabilir kod. Tarayıcı container'ları repoyu yazılabilir mount ediyor. Kitin kendi tehdit modelinde repo/config/tool/output sınırları açıkça belgelenmeli; veri biçimli config'e geçiş ve salt okunur kaynak/ayrı çıktı mount'u uyumluluk deneyiyle değerlendirilmelidir. Burada saldırı veya ele geçirilmiş tarayıcı gösterilmedi.

### 5. QA / release mühendisi

**Güçlü:** 93 çevrimdışı assertion, sentetik stack fixture'ları, bütünlük/tamper testleri, RC ile gerçek projede deneme kültürü mevcut.

**F09 — K, yüksek:** `.github/workflows/ci.yml` yalnız ShellCheck ve checksums koşuyor; self-audit secret/SAST çalıştırıyor. `tests/e2e.sh` PR zorunlu kontrolü değil. Release öncesi yerel e2e bunun yerini tam karşılamıyor. Çevrimdışı deterministik e2e PR kapısı; gerçek tarayıcı adaptör smoke testleri ayrı zamanlanmış iş olmalı. Atlanan testler raporda sayılmalı.

**F18 — K/Ö:** Linux/macOS iddiasına karşı CI Linux ile sınırlı; WSL2 gerçek cihazda doğrulanmamış olduğu karşılaştırma metninde belirtiliyor. Destek matrisi Bash/Python sürümleriyle açık olmalı. Dosya yolu boşlukları ayrıca sınanmalı: `scan.sh:421` değişen dosyaları, `scan.sh:1026` findings argümanını boşlukla bölünebilen string olarak geçiriyor. Bu çalışmada boşluklu yol uçtan uca denenmedi.

### 6. AI değerlendirme / uygulamalı araştırma

**Güçlü:** Kanıt eşiği, karşı örnekler, dev/holdout ayrımı, precision/recall ve provider hatalarının ayrı ele alınması olgun yaklaşım.

**F12 — K, yüksek:** `skills/sec-triage.skill.md:69` kanıt eksikliğinde varsayılan FP önerirken aynı akış UNCERTAIN de tanımlıyor. `tests/eval/triage_prompt.md` ve grader ikili REAL/FP sözleşmesi kullanıyor. “Güvensiz değil” ile “karar verecek bağlam yok” ayrımı kaybolabilir; yanlış negatif oranının gerçekten yükseldiği bu incelemede ölçülmedi. Eksik bağlamı UNCERTAIN olarak kaydeden ve otomatik allowlist'e sokmayan sözleşme yeni dev vakalarıyla ölçülmeli; prompt doğrudan değiştirilmemeli.

`tests/eval/README.md` varsayılan Claude backend'inin ölçülmediğini söylüyor; bu tarihsel kayıt güncel bir test sonucu sayılmaz. Korpus büyüklüğü anlatımı da 61/30 ile daha sonraki 36 holdout anlatımı arasında tutarsız. Korpus sayıları ve ölçüm raporu koddan üretilmeli; prompt hash'i, model kimliği, veri seti sürümü, abstention ve coverage birlikte raporlanmalı. Deep/AI-review pasları ve tarama çıktısına gömülmüş kötü niyetli talimatlara direnç ayrı değerlendirme ihtiyacı (F12).

### 7. Veri / raporlama

**Güçlü:** Kanıtın şiddet kaynağı korunuyor; Python HTML üreticisi metinleri escape ediyor; rapor tek dosya ve harici servis gerektirmiyor.

**F04 — D/K:** `lib/report_html.py:191` civarında bulunmayan `exit_code` temiz kabul ediliyor; sıfır dışındaki her kod “findings present (exit 1)” gösteriliyor. Araç hatası, eksik kapsam ve güvenlik bulgusu ayrılmalı. Rapor oluşturma zamanı ile taramanın zamanı ayrı tutulmalı; `scan.sh report` bugünün tarihini eski kanıta basabiliyor.

**F16 — K:** Evidence adaptör listesi (`lib/evidence.py:21`) gitleaks, semgrep, trivy, osv ve zizmor ile sınırlı. pip-audit, JS audit, checkov ve GuardDog boyutlarının ham bulguları ortak modele doğrudan alınmıyor. `scan.sh all` sonrası HTML'nin bütün boyutların tüm bulgularını içerdiği varsayılmamalı; önce kapsama matrisi, sonra eksik adaptörler gerekir.

**F19 — K/Ö:** Bulgu kimliği boyut+kural+dosya+satır (`lib/evidence.py:135`); satır kayması kimliği değiştiriyor. Aynı kural ve manifest konumundaki farklı paketler dedup sırasında birleşebilir. Paket adı/sürümü/purl, araç fingerprint'i ve commit bağlamıyla örnekler doğrulanmalı. Allowlist kontrolü exact-id ve mevcut dosya çiftleriyle sınırlı (`scan.sh:865`); alias eşleştirme/uygulanabilir boyut bilgisi olmadan otomatik fan-out yapılmamalı. Sahip, gerekçe, son tarih ve tekrar doğrulama bilgisi ortak karar kaydında tutulabilir.

### 8. Bakım / operasyon

**F20 — Ö:** Boyut başına süre, hata nedeni, atlama nedeni, dosya sayısı ve cache hit bilgisi performans kararlarını kanıta bağlar. Önce ölçüm, sonra cache ve monorepo kapsam optimizasyonu (F21). Cache doğruluğu araç/rule/config/kapsam/veri tabanı değişimlerini hesaba katmadan sağlanamaz.

**F22 — K:** Yerel planlarda evidence/HTML gibi mevcut özelliklerin toplu maddeleri ve eski “unreleased” durumları bulunuyor. `ROADMAP.local.md` R5.2 slice A'yı yapılmış ve unreleased gösteriyor; yerel HEAD kilit değişikliğinin main'de olduğunu kanıtlıyor, yayınlanmış olup olmadığı uzaktan doğrulanmadı. Yapılmış işler yeni geliştirme gibi yeniden listelenmemeli. Tek güncel backlog ile tarihsel araştırma notları arasında bağlantı kurulmalı.

## Korunması gereken ürün sınırları

Bu inceleme DAST/otonom saldırı yürütme, SaaS paneli, CSPM veya yeni tarayıcı sayısını artırmayı önermiyor. Mevcut yol haritasındaki ürün kimliği korunmalı. Ağsız rapor üretimi, isteğe bağlı ağır kontroller ve ham bulgu/yargı ayrımı sonraki geliştirmelerin kabul koşullarında kalmalı.

## Roadmap ile birleştirme güncellemesi — 8 Eylül 2026

Roadmap, uygulama planı, AI tasarımı ve wizard tasarımı ayrıca değerlendirildi. [Eşleme belgesi](roadmap-reconciliation-2026-09-08.md) mevcut özellikleri ve gerçek kalan işleri ayırır. Güncel sıra: F09 → F01/F05 → F02/F03/F04 → F06/F07/F08; ardından kapsam, kurulum ve ölçülmüş performans işleri. F12 kalibrasyon hattı bağımsızdır; F21 cache ve monorepo olarak iki teslimata ayrıldı. Aşağıdaki ilk öneri tarihçedir; güncel iş sırası backlog tablosudur.

## İlk planlama önerisi — güncel sıra backlog'da

Önce F01–F04 ve F09 ile bir “güvenilir kayıt” paketi seçilsin. F05/F06/F07 aynı güvenilirlik döneminde takip etsin. AI karar sözleşmesi F12 ayrı ölçüm kapısıyla yürüsün. Cache, monorepo ve yeni dağıtım kanalları ancak bu temel ve ihtiyaç ölçümleri hazır olduktan sonra planlansın. Ayrıntılı kabul kriterleri ve bağımlılıklar iş listesinde verilmiştir.
