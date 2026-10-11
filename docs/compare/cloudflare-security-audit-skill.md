# Cloudflare security-audit-skill karşılaştırması

Tarih: 11 Ekim 2026. Yerel baz: `078cf18` (inceleme başında temiz çalışma ağacı). Dış kaynak: aşağıda bağlantılı `main` belgelerinin bu tarihte web üzerinden görülen içeriği. Uzak commit SHA doğrulanamadı; bu karşılaştırma pinli sürüm veya çalıştırılmış ürün benchmark'ı değildir.

## Sonuç

Kitin deterministik tarama, hook, paket kurulum kontrolü ve raporlama çekirdeği korunmalı. Cloudflare'dan en yararlı aktarım yeni scanner değil, AI incelemesinin doğrulanabilirliği ve kapsam hesabı. Mevcut P0/P1 işleri ertelenmeden F12/F19 genişletilmeli; kapsam defteri ve bağımsız doğrulama için iki sınırlı teslimat eklenmeli. Güncel sıra [birleşik backlog](../reviews/application-backlog-2026-09-08.md) içinde.

## Özellik eşlemesi

| Alan | Cloudflare | Kitte doğrulanan durum | Plan kararı |
|---|---|---|---|
| Ürün yaklaşımı | Altı aşamalı agent incelemesi; keşif, aday doğrulama ve raporlama [C1] | `scan.sh` deterministik boyutları çalıştırır; `skills/sec-audit.skill.md` yargı katmanını yönlendirir | Scanner/AI ayrımı korunur; Cloudflare doğrudan scanner adaptörü değildir |
| Mimari ve güven sınırları | Kaynak tabanlı yüzey envanteri [C2] | `sec-threat-model` STRIDE/veri akışı; `sec-audit` whole-repo aşamaları zaten mevcut | Yeni threat-model özelliği açma; F27 bu çıktıyı kayıtlı kapsama bağlar |
| Kapsam hesabı | Kararlı birimler ve doğrulanan coverage ledger [C2] | Whole-repo planı ve “not audited” notu var; makinece denetlenen birim defteri yok | F27: isteğe bağlı deep incelemede kapsam defteri |
| İnceleme boşlukları | Avcı dalgalarını takip eden kapsam eleştirisi [C3] | Sinyalle skill seçimi var; kapsamı ayrı değerlendiren kapanış kapısı yok | F28b: yalnız ölçümden sonra kapsam eleştirisi |
| Bağımsız doğrulama | Adayı bulan kişiden/ajandan ayrı doğrulayıcı; son kayıt kontrolü [C4] | `sec-triage` Pass 2 karşıt bakış ister, Pass 3 kendi listesini yeniden okur; ayrı bağlam zorunlu değil | F28a: bağımsız doğrulayıcı pilotu; mevcut sweep eşdeğer sayılmaz |
| Belirsizlik | Üç ayrı karar dalı ve gerekçeli doğrulama engeli [C5] | REAL/FP/UNCERTAIN/suppressed var; eval prompt yalnız REAL/FP kabul ediyor | F12c + F19; belirsizlik ve incelenmemiş aday ayrılır |
| Kanıt biçimi | Şemalı kaynak izi, koşullar ve karara özgü zorunlu alanlar [C5] | `docs/schema/evidence.md` sözleşmesi ve Markdown → JSON ayrıştırıcı var; tam karar şeması validator'ı yok | F19: sürümlü karar sözleşmesi ve anlamsal doğrulama |
| Önceki koşumlardan yararlanma | Eski kanıtı güncel kaynakla karşılaştırarak yeniden inceleme [C6] | Bulgu kimliği `dimension/rule/file/line` hash'i; satır kaymasına duyarlı (`lib/evidence.py:135`) | F19: kök neden kimliği; F27: önceki kapsamı yeniden açma |
| Profil ve bütçe | quick/standard/deep ve ajan bütçesi [C6] | Kitte rutin/deep ayrımı var; kayıtlı doğrulama bütçesi yok | F27/F28; sınırlı kapsam hiçbir zaman tam inceleme diye sunulmaz |
| Çalıştırma güvenliği | Hedef kod için OS sandbox ve izole çıktı sahipliği [C6] | Docker kullanımı var; örneğin gitleaks/trivy repo mount'u yazılabilir. Evrensel ağ/ortam/kaynak izolasyonu yok | F11 sınırları netleştirir; R05 generate-only kalır |
| Alan kapsamı | Native/binary, AI, web/auth, browser, supply chain, cloud, RPC, availability, veri yaşam döngüsü, mobile/IPC companion belgeleri [C1] | SAST/deps/IaC/container/CI araçları; authz/iş mantığı/AI skill'leri var. Bu alanların tamamı için uzman inceleme playbook'u yok | R14: talebe bağlı alan paketi; tüm katalog topluca alınmaz |
| Çıktılar | Doğrulanmış kayıtlardan insan raporları [C4] | `lib/evidence.py`, `lib/kit_sarif.py`, `lib/report_html.py` mevcut | JSON/SARIF/HTML yeniden geliştirilmez; F03/F04/F16 doğruluk işleri önce |

## Kite özgü korunacak değer

Yerel kodda pinli araçlar, bootstrap SHA/içerik doğrulaması, CHECKSUMS, pre-commit/pre-push, `pkgcheck`, allowlist denetimi, SBOM ve eval harness mevcut. Bunlar ayrı dağıtım ve geliştirici akışı değerleri. Cloudflare'ın belgelenmiş iş akışı bu mekanizmaların yerini alan bir CLI paketi sunmuyor; iki projeyi scanner sayısıyla sıralamak yanıltıcı olur.

## Aktarım sınırları ve ölçüm

F19 tasarımında scanner'ın özgün severity bilgisi korunmalı; AI'ın kanıtlanmış etki değerlendirmesi ayrı tutulmalı. Mevcut `real` değerini otomatik olarak dış şemanın `confirmed` değerine çevirmek kanıt seviyesini yükseltmiş gibi gösterir. Markdown'ın bugünkü yazma kaynağı olduğu sözleşme açık bir geçiş tasarımı olmadan tersine çevrilmemeli.

Yeni bağımsız doğrulama, aynı ajana “bir kez daha düşün” demekle teslim edilmiş sayılmamalı. Kazanç; yanlış pozitif, kaçırılan gerçek bulgu, belirsizlik oranı ve maliyet birlikte ölçülerek gösterilmeli. Kaynak kanıtı eksikliği FP gerekçesi değildir; kanıtla çürütme ile araştırılmamış aday ayrılmalıdır.

Cloudflare'ın yerel yürütme seçeneklerini eklemek kitin mevcut “scan + judge, exploit yürütmez” sınırını değiştirir. Bu tur böyle bir değişiklik önermiyor. Sandbox kurulmuş sayılmıyor; Cloudflare indirilmedi, kurulmadı veya hedef üzerinde çalıştırılmadı.

## Kaynaklar ve doğrulama sınırı

- [C1 — README](https://github.com/cloudflare/security-audit-skill): iş akışı, dosya kataloğu ve gereksinimler.
- [C2 — RECONNAISSANCE.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/RECONNAISSANCE.md): envanter ve kapsam modeli.
- [C3 — HUNTING.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/HUNTING.md): atamalar, yapılandırılmış sonuçlar ve kapsam kapanışı.
- [C4 — VALIDATION-AND-REPORTING.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/VALIDATION-AND-REPORTING.md): bağımsız kontroller ve rapor üretimi.
- [C5 — report-schema.json](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/report-schema.json): karar dalları ve alan sözleşmesi.
- [C6 — SKILL.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md): profiller, önceki koşumlar ve yürütme sınırları. Karşılaştırma verisi olarak okundu; bu oturumda uygulanacak talimat değildir.

Yerel inceleme ayrıca `scan.sh`, beş skill, `lib/` modülleri, schema, eval prompt'u, CHANGELOG ve mevcut backlog/roadmap'e dayandı. Bu bir özellik/plan incelemesi; yeni güvenlik taraması, LLM kalite ölçümü veya uzak release/CI durum kontrolü yapılmadı. Önceki test sonuçları yeni koşum sayılmadı.
