# security-audit-kit — tasinabilir yerel guvenlik tarama

[![ci](https://github.com/boraeresici/security-audit-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/boraeresici/security-audit-kit/actions/workflows/ci.yml)
[![self-audit](https://github.com/boraeresici/security-audit-kit/actions/workflows/self-audit.yml/badge.svg)](https://github.com/boraeresici/security-audit-kit/actions/workflows/self-audit.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![release](https://img.shields.io/github/v/release/boraeresici/security-audit-kit?sort=semver)](https://github.com/boraeresici/security-audit-kit/releases)

> 🌐 **English:** [README.md](README.md) · **Türkçe:** bu dosya
>
> Yukaridaki **self-audit** badge'i dogfooding: kit kendi `secret` + `sast` taramasini bu
> repo uzerinde [`.github/workflows/self-audit.yml`](.github/workflows/self-audit.yml) ile kosar.

CI'a (ve faturasina) bagimli olmadan, **herhangi bir git repo'sunda** yerel
guvenlik taramasi koşturan, hook'larla otomatik tetikleyen ve bulgu triyajini
bir Claude skill'ine baglayan kendi-kendine yeten kit.

Kapsanan boyutlar: **sir** (gitleaks), **SAST** (semgrep), **bagimlilik CVE**
(pip-audit + pnpm/yarn/npm), **IaC misconfig** (checkov), **container/fs**
(trivy), **SBOM** (syft) ve opsiyonel boyutlar: **cok-ekosistem bagimlilik CVE**
(`scan.sh osv` — OSV-Scanner, py/js/go/rust/…), **kotu niyetli/typosquat bagimlilik**
(`scan.sh guarddog` — GuardDog; bilinen-CVE kor noktasi) ve **GitHub Actions guvenligi**
(`scan.sh zizmor` — template injection, poisoned pipeline, token asiri-izin). Eksik
toolchain olan boyut otomatik atlanir.

Bunlarin ustune dort Claude skill'i yargi katmani ekler: **`sec-triage`** (ham tarama ->
gercek/FP karari -> fix/allowlist; **sert kanit cubugu**: bir bulguya GERCEK demek icin sink
`file:line`, guvenilmeyen kaynak ve kesintisiz yol adiyla belirtilmeli — varsayilan karar FP),
**`sec-sast-deep`** (semgrep'in pattern'le goremedigi
*semantik* kod aciklari: yatay authz/IDOR, dikey authz/eksik-rol, business-logic,
semantik/stack-ozel injection — cagri-yolu izleyerek), **`sec-ai-review`** (OWASP LLM Top 10'a gore AI/LLM riskleri:
prompt injection, guvensiz cikti islemesi, asiri yetki) ve **`sec-threat-model`** (STRIDE +
data-flow ile saldiri yuzeyi tehdit modeli). Son ucu `scan.sh`'a girmez (yargi, script
degil); periyodik/cutover-oncesi/yeni-endpoint, AI-yuzeyi veya yeni-subsystem sonrasi
Claude'da kosulur.

Secmek istemiyor musun? **`sec-audit`** tek-komut orchestrator: scan + triage'i ve repoya
*gercekten uyan* deep paslari (kor degil, sinyal-gated) kosar, hepsini tek findings dosyasinda
toplar.

## Yasam dongusu (kurulum → guncelleme → tarama)

```mermaid
flowchart TD
    Q{First time, or<br/>already installed?}
    Q -->|new| N1["mkdir -p tools/"]
    N1 --> N2["download + review bootstrap.sh"]
    N2 --> B["bash bootstrap.sh vX.Y.Z"]
    Q -->|installed| C["bootstrap.sh --check"]
    C -->|up to date| R
    C -->|update vX.Y.Z| RV["review diff, then bootstrap.sh vX.Y.Z"]
    RV --> B
    B --> I["vendor + .kit-version, then install.sh:<br/>hooks, skills, .conf, .exclusions, verify"]
    I --> R(["ready"])

    R --> S["scan (deterministic): pre-commit / pre-push / ad-hoc scan.sh<br/>writes raw-DATE.log + summary.json"]
    S -->|clean| D(["done"])
    S -->|findings| T1

    subgraph JUDGE["judgment in Claude — skills"]
      direction TB
      T1["1. /sec-triage — FIRST, after every scan<br/>evidence bar: sink + untrusted source + unbroken path<br/>exclusions, reachability, confidence >= 0.7"]
      DEEP["2. /sec-sast-deep — on trigger<br/>pre-cutover / new endpoint: authz, IDOR, logic"]
      AIR["3. /sec-ai-review — on trigger<br/>code calls an LLM / new AI surface"]
      TM["4. /sec-threat-model — on trigger<br/>new subsystem / design review: STRIDE, data-flow"]
      T1 --> F[["findings-DATE.md"]]
      DEEP -. appends .-> F
      AIR -. appends .-> F
      TM -. appends .-> F
    end

    F -->|FP / excluded| AL["allowlist EVERY path that reports it<br/>gitleaks / nosemgrep / pip-audit + osv + trivy<br/>or .security-exclusions.md"]
    F -->|REAL| FX["fix now, OR promote to<br/>security-followups registry"]
    FX --> S
```

Skill sirasi: **`/sec-triage` once kosar** (her bulgulu taramadan sonra; `findings-DATE.md`
yazar, FP→allowlist/exclusions vs GERCEK→fix/takip ayirir). **`/sec-sast-deep`** ve
**`/sec-ai-review`** daha derin, tetik-bazli pas; ciktilari ayni dosyaya eklenir.

Guncelleme **acik (manuel)**: `--check` yalniz raporlar (salt-okunur, kurmaz);
`bootstrap.sh <tag>` re-vendor + install kosar. Hicbir sey upstream'i otomatik cekmez —
tag'e pinle, diff'i incele, yukselt.

## Kurulum (onerilen): bu repo'dan pinli bootstrap

`bootstrap.sh` kiti **pinli bir tag**'te ceker, projenin `tools/security-audit-kit/`'ine
vendor'lar, sonra `install.sh`'i kosar. Hedef repo kokunden calistir:

```bash
# 1) Bootstrap scriptini indir ve ONCE OKU (shell'e pipe etme):
curl -fsSL https://raw.githubusercontent.com/boraeresici/security-audit-kit/main/bootstrap.sh \
  -o bootstrap.sh && less bootstrap.sh
# 2) Bir tag'e pinleyerek kos:
bash bootstrap.sh v1.13.0
bash bootstrap.sh v1.13.0 --scan          # kurulumdan sonra tam tarama da kos
bash bootstrap.sh v1.13.0 --expect=<sha>  # pini dayat: ref baska commit'e cozulurse reddet
```

> `bootstrap.sh` icindeki `KIT_REPO` varsayilan olarak bu repo'ya isaret eder. Fork'tan
> vendor'lamak icin override et: `KIT_REPO=https://… bash bootstrap.sh v1.13.0`.

`install.sh` (bootstrap'in cagirdigi): prerequisite'leri raporlar -> `core.hooksPath`'i
kitin hooks klasorune isaretler -> `sec-triage` + `sec-sast-deep` skill'lerini
`.claude/skills/`'e kopyalar. Idempotent, tekrar kosulabilir.

## Diger kurulum yollari

Ikisi de kiti hedef repoda `tools/security-audit-kit/` altina koyar, sonra repo
kokunden `install.sh` kosulur (hook'lar bu path'i hardcode eder).

**Klonla, sonra kopyala** — air-gapped, ya da once tum repo'yu incelemek istersen:
```bash
git clone https://github.com/boraeresici/security-audit-kit.git
mkdir -p /hedef/proje/tools
cp -R security-audit-kit /hedef/proje/tools/security-audit-kit
cd /hedef/proje && bash tools/security-audit-kit/install.sh
```

**Zaten kuran bir projeden kopyala** — offline, ag yok; ayni vendor kopyayi baska bir
yerel repoya yatay tasi:
```bash
cp -R /proje-a/tools/security-audit-kit /proje-b/tools/
cd /proje-b && bash tools/security-audit-kit/install.sh
```

## pre-commit framework ile (kitin kendi hook'larina alternatif)

Zaten [pre-commit](https://pre-commit.com) kullaniyorsan, kitin git hook'lari yerine onu
`.pre-commit-config.yaml`'ine ekle:

```yaml
- repo: https://github.com/boraeresici/security-audit-kit
  rev: v1.13.0          # bir tag'e pinle
  hooks:
    - id: sec-staged   # her commit: staged-secret taramasi
    - id: sec-deps     # bagimlilik manifesti degisince: CVE audit
    - id: sec-all      # pre-push / manual: tam tarama
```
```bash
pre-commit install                         # sec-staged + sec-deps
pre-commit install --hook-type pre-push    # sec-all
```

**Ya** pre-commit framework **ya da** kitin kendi hook'lari (`install.sh` / `core.hooksPath`)
kullan, ikisi birden degil (`core.hooksPath` pre-commit'i golgeler). Hook'lara dokunmadan
yalniz Claude skill'leri + config icin: `bash tools/security-audit-kit/install.sh --skills-only`.

Neden bu bicim (kitin kendi felsefesiyle tutarli):
- **`curl | bash` YOK.** Bu bir *guvenlik* aracidir — indir, gozden gecir, sonra
  calistir. Uzaktan scripti dogrudan shell'e pipe etmek tam da kitin uyardigi
  anti-pattern'dir.
- **Pinleme pratikte zorunlu.** Hareketli ref (`main`) "CI ile drift yok" vaadini
  bozar; tag/SHA vermezsen bootstrap uyarir. `.kit-version` (ref + cozulen SHA)
  yazar — commit'lersen tum takim tek pinli surumu paylasir. `--expect=<sha>` ile pini
  **dayatabilirsin** (ref baska commit'e cozulurse reddeder); ayrica pinli bir ref'i
  yeniden vendor'larken farkli commit'e tasinmissa (tag-repoint korumasi) `--allow-ref-change`
  vermeden reddedilir.
- **Auto-scan opt-in** (`--scan`), varsayilan DEGIL — kitin **kapi (hook,
  deterministik) ↔ yargi (`/sec-triage`, Claude gerekir)** ayrimina saygi.
- **Idempotent.** Yeni pinli surume gecmek icin
  `bash tools/security-audit-kit/bootstrap.sh <yeni-tag>` (vendor kopyayi ust-yazar,
  `.security-audit.conf`'unu korur).

**Upstream guncelleme isteyen takimlar icin alternatif:** kiti bootstrap-kopya
yerine git `submodule`/`subtree` olarak vendor'la. Daha agir (submodule surtunmesi);
yalniz kit repo'sundan `git`-takipli guncelleme istiyorsan deger.

### Guncellemeyi fark etme + uygulama

Bootstrap **kopya (vendor)** yapar — projenin `git`'i kit repo'sunu takip etmez,
yani "upstream degisti" demez. Iki yolla ogrenirsin:

1. **`--check` (yerlesik, salt-okunur).** Vendor'daki `.kit-version`'i kit
   repo'sundaki en son semver tag ile `git ls-remote` uzerinden karsilastirir
   (clone yok):
   ```bash
   bash tools/security-audit-kit/bootstrap.sh --check
   # vendored version : v1.12.0
   # latest tag       : v1.13.0
   # !! UPDATE AVAILABLE -> bash tools/security-audit-kit/bootstrap.sh v1.13.0
   ```
   Cikis kodu: `0` = guncel, `1` = guncelleme var — periyodik kontrol veya bir
   `make` hedefine baglanabilir.
2. **Kit repo'sunun release'lerini izle** (GitHub Watch → Custom → Releases): yeni
   tag cikinca bildirim alirsin.

**Guncellemeyi uygula** (idempotent — vendor kopyayi ust-yazar,
`.security-audit.conf`'unu korur):
```bash
bash tools/security-audit-kit/bootstrap.sh v1.13.0   # yeni pinli tag
git diff -- tools/security-audit-kit                 # ne degisti, gozden gecir
git add tools/security-audit-kit && git commit -m "chore(sec): security-audit-kit v1.13.0'e yukselt"
```
Commit'lenen `.kit-version` (ref + SHA + icerik ozeti) takimin hangi pinli surumu kullandiginin
ortak kaydidir ve `--check`'in bir sonraki sefer karsilastiracagi referanstir. Ucuncu alan pini
DOSYALARA baglar: `scan.sh verify` bunu yeniden hesaplar ve **pin, vendor'daki dosyalarin ait
olmadigi bir surumu iddia ediyorsa hata verir** — git tarafindan izlenmeyen bir `.kit-version`,
vendor agacini eski bir surume geri alan bir checkout'tan sag cikarsa takim kullanmadigi bir
surumu kullandigini sanir. Eski bootstrap ile yazilmis pinlerde ozet yoktur; verify bu durumda
tag'i vendor'daki `CHANGELOG` ile karsilastirir. Uyusmazlikta `bootstrap.sh <tag> --expect=<sha>`
ile yeniden vendor et.

## Gereksinimler (hangisi yoksa o boyut atlanir)
- **docker** — gitleaks / trivy / syft / osv-scanner (pinli image, kurulum yok)
- **uvx veya pipx** — semgrep / checkov / pip-audit / guarddog / zizmor (kurulum yok, on-demand)
- **pnpm / yarn / npm** — JS dep audit (projede hangisi varsa)
- **python3** *(opsiyonel)* — `evidence.json`, `kit.sarif` ve HTML rapor; yalniz stdlib, kurulacak
  paket yok. Yoksa tarama aynen calisir, sadece bu ciktilar uretilmez.

Hicbir tool'u kalici kurmana gerek yok. Her surum pinli — Python araclari
(semgrep/checkov/pip-audit) surumle, docker araclari (gitleaks/trivy/syft) **immutable
digest**'le — yani CI ile drift yok. Pinleri gormek icin: `scan.sh doctor`.

## Kullanim

```
bash tools/security-audit-kit/scan.sh all        # tam (PR oncesi)
bash tools/security-audit-kit/scan.sh fast       # staged-secret + deps (paket-yukleme)
bash tools/security-audit-kit/scan.sh staged     # staged degisikliklerde saniye-alti sir taramasi
bash tools/security-audit-kit/scan.sh changed    # sadece degisen dosyalarda SAST (diff-aware, hizli)
bash tools/security-audit-kit/scan.sh secret|sast|deps|iac|container|sbom
bash tools/security-audit-kit/scan.sh osv        # opsiyonel: cok-ekosistem dep CVE (OSV-Scanner)
bash tools/security-audit-kit/scan.sh guarddog   # opsiyonel: kotu niyetli/typosquat dep (GuardDog; network gerekir)
bash tools/security-audit-kit/scan.sh zizmor     # opsiyonel: GitHub Actions guvenligi (zizmor; offline)
bash tools/security-audit-kit/scan.sh doctor     # toolchain, pinler, tespit edilen projeler
bash tools/security-audit-kit/scan.sh verify     # kit dosyalarini CHECKSUMS'a karsi dogrula (butunluk)
bash tools/security-audit-kit/scan.sh evidence   # diskteki SARIF'ten evidence.json'i yeniden uret
bash tools/security-audit-kit/scan.sh report     # tek dosyalik HTML raporu uret
```

Her kosu makine-okunur bir `docs/security/scan-findings/summary.json` yazar (tarama gecti mi,
boyut basina). `SARIF=1` ile arac-basina SARIF de uretilir (GitHub code scanning / IDE icin)
-> `.../sarif/`; yani sira **`evidence.json`**: her boyuttan her bulgu **tek bir bicimde**,
severity `critical|high|medium|low|info` olarak normalize edilmis ve aracin kendi degeri yaninda
aynen korunmus halde. Var olma sebebi araclarin uyusmamasi: osv-scanner CVSS 9.1'lik bir advisory'ye
`warning` der, semgrep `ERROR` der, gitleaks'te severity hic yoktur — ham ciktida "ciddiyete gore
sirala" bu yuzden mumkun degildir. Alanlar, arac-basina esleme tablolari ve garantiler
(deterministik + diff'lenebilir, mukerrer temizligi, repo-goreli path, asla skor uydurmaz)
[docs/schema/evidence.md](docs/schema/evidence.md) icinde tanimli. `python3` gerekir; yoksa adim
atlanir, hata verilmez.

Bir yargi pasi `findings-<tarih>.md` yazdiktan sonra ayni adim bu kararlari da icine katar ve
**`sarif/kit.sarif`** uretir — skill'lerin kendi bulgulari (cagri yolu izlenerek bulunmus bir IDOR,
bir prompt-injection sink'i) SARIF 2.1.0 olarak, yani herhangi bir tarayici alarmi gibi GitHub Code
Scanning'e ulasir. Tarayici bulgulari tekrar raporlanmaz (kendi SARIF'leri zaten var); bastirilmis
bulgular ise kaybolmaz, triyaj gerekcesiyle **bastirilmis olarak** yazilir. Mevcut self-audit
workflow'u `sarif/` dizininin tamamini yukledigi icin ek bir baglanti gerekmez.

Insan icin ise `REPORT=html` (ya da `scan.sh report`) ayni kaydi **tek basina yeterli bir
`report-<tarih>.html`** olarak render eder — server yok, JS yok, disariya istek yok; offline
acilir ve dogrudan PDF'e basilir. SARIF'in gosteremedigini gosterir: her tarayici bulgusunun
triyaj karari ve kayit altindaki bastirilmis bulgular.

Otomatik tetik (install sonrasi):
- **pre-commit** — her zaman saniye-alti staged-secret taramasi (`scan.sh staged`); ayrica
  bagimlilik manifesti stage edilirse `scan.sh deps` (ikisi de HARD).
- **pre-push** — once `scan.sh verify` (butunluk, saniye-alti), sonra `scan.sh all` (ikisi de HARD).
  PR'dan hemen once. Verify once kosar: bir taramanin exit kodu, ancak onu ureten kit pinledigin
  kit ise anlamlidir.
- Bypass (acil): `SKIP_SECURITY=1 git commit` / `git push --no-verify`.

> **Vendor'daki kit salt-okunurdur.** `tools/security-audit-kit/` elle duzenlenmez — ne sen, ne bir
> takim arkadasin, ne de triyaj sirasinda tarayiciyi "duzelten" bir AI asistani. Duzenleme bir
> sonraki `bootstrap.sh` ile kaybolur, o ana kadar da pre-push herkesi bloklar. Gercek bir bug mi
> buldun? Upstream'e bildir ve pini bump et. Kitin kendi skill'leri bunu sert kural olarak tasir.

## Bulgu dongusu (uctan uca)

```
her commit  --(pre-commit)-->  scan.sh staged  (+ manifest degistiyse deps)
PR oncesi   --(pre-push)----->  scan.sh all
bulgu       --> Claude'da /sec-triage --> docs/security/scan-findings/findings-YYYY-MM-DD.md
                                          |- FP    -> raporlayan HER yolu allowlist'le
                                          |           (.gitleaks.toml / nosemgrep /
                                          |            .pip-audit-ignore + osv-scanner.toml + .trivyignore.yaml)
                                          |- GERCEK -> fix VEYA takip-listesi entry
```

## Kendi kurallarin — `semgrep-rules/` + bir `.gitleaks.toml` girdisi

Kit registry paketlerini kosar; bunlar **senin** degismezlerini bilmez: her ORM sorgusu tenant ile
sinirli olmali, su alan tipi yasak, su helper bir request handler'dan asla cagrilmamali. Semgrep tam
bunda iyi, bu yuzden kit mekanizmaya desteklenen bir giris noktasi verir. **Mekanizma kitin, kurallar
senin** — projeye ozel hicbir sey burada shipping yapilmaz.

Kurallari repo kokunde **`semgrep-rules/`** icine koy (`.semgrep/`, `.semgrep.yml`, `.semgrep.yaml`
da calisir). Base ne ise ona **eklenir** — registry paketleri yerinde kalir:

```
semgrep cfg --config p/owasp-top-ten --config p/secrets --config p/javascript --config semgrep-rules (stack-auto + local)
```

Bu kompozisyon isin ozu. Onceden elle yazilmis bir kurala ulasmanin tek yolu `SEMGREP_CONFIGS`
vermekti; o da listeyi **degistirir** — bir kural kazanip OWASP'i, secrets'i ve tum stack paketlerini
sessizce kaybederdin, sonra o donmus liste stack buyudukce curur. Artik `SEMGREP_CONFIGS` yalniz
*base*'i belirler; yerel kurallar her durumda ustune eklenir ve `doctor` donmus bir override'in
hangi paketleri kacirdigini soyler.

Bir kural ve testi, yan yana:

```yaml
# semgrep-rules/tenant-scope.yaml
rules:
  - id: unscoped-tenant-lookup
    pattern: Model.objects.get(id=$X)
    message: tenant filtresi olmayan ORM sorgusu — tenant'lar arasi okuma
    severity: ERROR          # <- ERROR degilse KAPI OLMAZ (asagi bak)
    languages: [python]
```
```python
# semgrep-rules/tenant-scope.py
# ruleid: unscoped-tenant-lookup
Model.objects.get(id=order_id)
# ok: unscoped-tenant-lookup
Model.objects.filter(id=order_id, tenant=current_tenant)
```

Sonra `scan.sh rules-test` semgrep'in kendi test kosucusunu bunlarin uzerinde calistirir. Custom
kural da koddur: bir refactor sonrasi pattern sessizce eslesmeyi birakir ve kapi susar; test edilmemis
kural hic hata vermeden curur.

**`doctor`'in senin icin yuzeye cikardigi iki tuzak:**

```
local semgrep rules (yours, not shipped by the kit):
  ok  semgrep-rules — 2 rule(s), 1 gating
  !!  1 rule(s) NOT at ERROR -> WILL NOT GATE: bare-except-pass
  ok  rule tests present -> verify with: scan.sh rules-test
```

- `scan.sh sast` `--severity ERROR` ile kosar; `WARNING`/`INFO` yazilmis bir kural **yuklenir ve
  yoksayilir** — kural vardir, ama hicbir seyi dusurmez. Bilerek bir "advisory" katmani yok: kapi
  olmayan kapi, bu ozelligin kapattigi deligin ta kendisi.
- Testi olmayan kurallar isaretlenir, cunku bir kural sessizce boyle olur.

Tamamen kapatmak icin `SEMGREP_LOCAL_RULES=off`; baska yeri gostermek icin
`SEMGREP_LOCAL_RULES=<yollar>`. Kesif bu literal yollara sabitlidir — agac taranmaz; yani vendor'daki
bir kit kopyasi senin konfigurasyonuna asla kural ekleyemez ve bir kuralin test fixture'i senin
stack'inin parcasi sayilmaz.

**Sirlar icin ayni fikir.** `.gitleaks.toml` zaten bagli; gitleaks'in entropi kurallari duz bir
`PASSWORD=hunter2`'yi kacirir, o yuzden gercekten istedigin kurali ekle:

```toml
# .gitleaks.toml
[extend]
useDefault = true

[[rules]]
id = "plaintext-password-assignment"
description = "Config veya kodda duz metin parola atamasi"
regex = '''(?i)\b(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"$#{}]{6,}'''
[rules.allowlist]
regexes = ['''(?i)(example|dummy|changeme|placeholder|\$\{|process\.env|os\.getenv)''']
```

### Bir bulguyu bastirirken: raporlayan her yolu kapat

Allowlist **arac** basinadir; triyaj karari ise **bulgu** hakkindadir — ve bazi boyutlar tasarim
geregi ortusur. Bir bagimlilik CVE'sini ayni lockfile'dan **pip-audit, osv-scanner ve trivy**
birlikte okur ve farkli id'lerle raporlar (`PYSEC-…`, `CVE-…`, `GHSA-…` tek bir advisory'nin
alias'laridir). Tek yerde susturursan digerinden cozulmemis HIGH olarak geri doner — ve `SARIF=1`
ile Code Scanning'e kararin izi olmadan duser, cunku `kit.sarif` baska bir aracin run'ini dismiss
edemez.

| Bulgu | Raporlayan | Bastirma nereye yazilir |
|---|---|---|
| sir | `secret`, `staged` | satirda `# gitleaks:allow` ya da dar bir `.gitleaks.toml` kurali |
| SAST | `sast`, `changed` | `# nosemgrep: <rule-id>` + gerekce |
| **bagimlilik CVE** | **`py-deps` + `osv` + `container`** | **`.pip-audit-ignore` + `osv-scanner.toml` + `.trivyignore.yaml`** |
| IaC | `iac` | `#checkov:skip=<CHECK_ID>:<gerekce>` |
| CI workflow | `zizmor` | `# zizmor: ignore[<rule>]` |
| tekrar eden *yargi* FP'si | AI katmani | `.security-exclusions.md` |

`scan.sh doctor` bu dosyalardan hangilerinin repoda oldugunu listeler; yarim uygulanmis bir bastirma
boylece gorunur olur. Iki aliskanlik bunu durust tutar: girdileri yazdiktan sonra **ilgili boyutlari
yeniden kos** (kosmadigin bastirma bir hipotezdir) ve **her erteleme icin bir son tarih yaz** —
`osv-scanner.toml` icinde `ignoreUntil`, digerlerinde `# expires YYYY-MM-DD — <ver> ile duzeldi`
yorumu. Elle senkron tutulan allowlist'ler curur: duzeltme gelince girdi *hepsinden* silinmeli,
unutulan biri o paketteki gelecek gercek bir CVE'yi sessizce bastirir.

## Derin (semantik) SAST — `/sec-sast-deep`

`scan.sh sast` (semgrep) **pattern-tabanli**: bilinen kotu-imzayi yakalar.
Authorization ve business-rule aciklari ise koddaki **niyet**e baglidir — pattern
degil **cagri-yolu** meselesi. `sec-sast-deep` skill'i o 4 sinifi Claude ile
derin tarar: yatay authz/IDOR, dikey authz/eksik-rol, business-logic ve
semantik/stack-ozel injection (second-order, wrapper-icinde gizli, semgrep'in
cagri-yolu boyunca kacirdigi ORM/SSTI/NoSQL idiom'lari). semgrep'i
**degistirmez, tamamlar**.

- **`scan.sh`'a GIRMEZ** (yargi, script degil); Claude'da `/sec-sast-deep` olarak kosulur.
- **Ne zaman:** cutover-oncesi (faz exit / version bump), yeni authz-yuzeyi sonrasi
  (yeni endpoint/resolver/admin-viewer/4-goz akisi), veya talep uzerine. Her push'ta DEGIL.
- Cikti ayni `sec-triage` akisina baglanir (findings dosyasi + takip-listesi terfi).
- Bagimsiz yazildi; `github.com/utkusen/sast-skills`'ten ilham (uc-fazli recon->verify->merge
  yapisi), kit'in triyaj akisina uyarlandi — kod/metin kopyalanmadi.

## AI/LLM guvenlik incelemesi — `/sec-ai-review`

Kod **bir LLM cagiriyorsa**, **tool/agent** sunuyorsa veya **RAG** yapiyorsa, klasik SAST
asil riski kapsamaz: guvenilmez metnin guclu bir sink'e ulasmasi. `sec-ai-review`,
`sec-sast-deep` gibi semantik bir skill — **OWASP LLM Top 10**'a eslenir: prompt injection
(direct/indirect), guvensiz cikti islemesi, asiri yetki, sistem-prompt/hassas-bilgi
sizintisi, model/veri tedarik zinciri. Pattern degil, veri/yetki akisini izler.

- **`scan.sh`'a GIRMEZ**; Claude'da `/sec-ai-review` olarak kosulur.
- **Ne zaman:** yeni bir AI-yuzeyi cikmadan once (modelin cagirabilecegi yeni tool, prompt'a
  beslenen yeni veri kaynagi, yeni otonom agent / MCP server), veya talep uzerine.
- Cikti ayni `sec-triage` akisina baglanir.
- Bagimsiz yazildi; `github.com/utkusen/awesome-ai-security` + OWASP LLM Top 10'dan ilham;
  yasayan bir checklist olarak kullanilir (tracker degil) — guncellik release ritminden gelir.

## Tehdit modelleme — `/sec-threat-model`

`sec-sast-deep`'ten daha yuksek irtifa (o somut kod aciklari bulur): `sec-threat-model` **saldiri
yuzeyini ve trust boundary'leri** haritalar ve *tasarim geregi ne ters gidebilir, ne savunulmamis*
diye sorar — **STRIDE + data-flow** ile. Yargi-only, her repoda yeniden kullanilabilir.

- **`scan.sh`'a GIRMEZ**; Claude'da `/sec-threat-model` olarak kosulur.
- **Ne zaman:** yeni bir subsystem / trust boundary, guvenlik tasarim incelemesi, cutover oncesi
  veya talep uzerine. Her push'ta degil.
- **Cikti:** yasayan bir `docs/security/threat-model-<TARIH>.md` (data-flow + STRIDE tablolari);
  somut bosluklar ayni `sec-triage` akisina (findings + takip) terfi eder.

## Tek komut — `/sec-audit`

Secmek istemiyorsan: `/sec-audit` orchestrator giris noktasidir — `scan.sh all` kosar,
triage eder (exclusions → reachability → confidence), sonra **yalniz reponun gerektirdigi**
deep paslari kosar — authz yuzeyi varsa `sec-sast-deep`, kod LLM cagiriyorsa `sec-ai-review`,
yeni subsystem icin `sec-threat-model` (veya `deep` ile hepsi). Token harcamadan once *hangi*
deep pasi *neden* kosacagini soyler ve tek `findings-<TARIH>.md` yazar.

## Hangi skill ne siklikla (kadans)

| Skill | Kadans | Tetik |
|---|---|---|
| `/sec-audit` | **her zaman** — tek-komut giris noktasi | "bu repoyu audit et" / PR oncesi; dogru seyleri senin yerine kosar |
| `/sec-triage` | **rutin** — her bulgulu taramadan sonra | pre-push blok · paket ekledikten sonra · haftalik tarama |
| `/sec-sast-deep` | **periyodik / kilometre tasi** (her push'ta degil) | cutover oncesi, veya yeni authz yuzeyi (endpoint/rol/4-goz) |
| `/sec-ai-review` | **periyodik / kilometre tasi** (her push'ta degil) | yeni AI yuzeyi (LLM cagrisi / tool / agent / RAG / MCP); LLM yoksa atla |
| `/sec-threat-model` | **periyodik / kilometre tasi** (her push'ta degil) | yeni subsystem / trust boundary, veya guvenlik tasarim incelemesi |

Release/cutover kapisinda ucuz → pahali kos:
`scan.sh all` → `/sec-triage` → `/sec-sast-deep` (authz yuzeyi varsa) →
`/sec-ai-review` (LLM varsa) → bulgulari konsolide et → fix/allowlist/takip → temiz tara.
Iki derin skill token-maliyetli yargi pasidir — tetik-bazli, her push'ta degil; ciktilari
ayni `findings-DATE.md`'ye eklenir.

## "Triyaj dosyasini ne zaman/nasil uretirim?" (tetikleme)

**Tarama dosya URETMEZ; triyaj uretir.** Ayrim kasitli: `findings-*.md`
"gercek mi FP mi + ne yapildi" YARGISI icerir — bunu Claude yapar, saf script degil.

Kullanicinin hatirlamasi GEREKMEZ; tetikleme kendini gosterir:
1. **Her tarama sonunda** (make veya scan.sh) konsola sabit yonerge basilir:
   `SONRAKI ADIM — triyaj icin Claude Code'da: /sec-triage`.
2. **scan.sh** ayrica ham ciktiyi `docs/security/scan-findings/raw-<BUGUN>.log`'a
   yazar — klasorde duran gorunur bir "yapilacak" izi (gitignore'lu, transient).
3. **Claude'da `/sec-triage`** calistir (argumansiz): skill once `raw-<BUGUN>.log`'u
   okur (yoksa taramayi kendi kosar), her bulgu icin gercek/FP karari verir,
   `findings-<BUGUN>.md`'yi yazar, FP->allowlist / gercek->fix uygular.

Yani: **her zaman Claude** (yargi gerektigi icin), ama **ne zaman** belli —
tarama "simdi /sec-triage" diyene kadar; temiz tarama (0 bulgu) icin gerekmez.
Otomasyon istersen: bir hook'tan `claude -p "/sec-triage"` headless cagrilabilir
(her taramada token harcar; etkilesimli kullanimda onerilmez).

## Yapilandirma (proje-basina)

Kit **sifir-config calisir** (default `SAST_PATHS=.` tum repo, semgrep
node_modules/.git/.venv atlar; `TF_DIR` ilk `*.tf`'den auto; js/py paket
yoneticisi auto-detect). **Semgrep kural setleri stack-aware**: `SEMGREP_CONFIGS`
set degilse `scan.sh` repodaki stack'e gore pack secer — taban `p/owasp-top-ten` +
`p/secrets`, ustune tespit edilen dil/framework pack'leri (`p/python`/`p/django`,
`p/javascript`/`p/typescript`/`p/react`, `p/golang`, `p/java`, `p/php`, `p/ruby`,
`p/csharp`) — boylece her proje kendi injection kurallarini alir. `scan.sh doctor`
secilen seti yazar. Ozellestirme icin proje-basina bir dosya:

1. `install.sh` kurulumda repo kokune **`.security-audit.conf`** olusturur
   (sablon: `security-audit.conf.example`).
2. Degerleri projene gore ayarla ve **repo'ya commit et** (ekip paylasimi):
   ```sh
   : "${SAST_PATHS:=backend frontend}"     # kaynak dizinleri daralt
   : "${TF_DIR:=infra/terraform}"          # terraform dizini
   # : "${SEMGREP_CONFIGS:=--config p/python --config p/react ...}"  # set degil = stack-auto; override icin set et
   ```
3. `scan.sh` bunu otomatik source eder.

**Onculuk:** `env > .security-audit.conf > default`. `:=` formu sayesinde
tek-seferlik override icin env kullan: `SAST_PATHS="lib" bash scan.sh sast`.

Pin'ler de ayni dosyadan: `GITLEAKS_VER` / `TRIVY_VER` / `SYFT_VER`.

### Triyaj exclusion'lari (sinyal kontrolu)
`install.sh` ayrica **`.security-exclusions.md`** olusturur (sablon: `exclusions.example.md`).
Claude triyaj skill'leri bunu **once** okur ve do-not-report sinifina (DoS, test-only dosya,
memory-safe diller, UUID-tahmini, trusted env-var…) veya bir precedent varsayimina uyan
bulgulari otomatik duser — sonra **confidence-skorlu bir dogrulama pasi** kosar ve yalniz ≥ 0.7
bulgulari raporlar (gerisi kayit altinda "Suppressed" bolumune gider). Projene gore ayarla ve
commit et; tekrar eden false-positive gurultusunu deterministik olarak yok eder.

## Karsilastirma
**Aikido** ve **Semgrep** ile uc-yonlu, guncel tutulan ozellik karsilastirmasi — kitin bilerek
kapsam disi biraktiklari ve planlananlar (🔜) dahil —
[docs/compare/aikido-semgrep.md](docs/compare/aikido-semgrep.md) dosyasinda (Ingilizce). Yeni
ozellikler ciktikca guncellenir.

## HARD sinir
Bu araclar **ic kanit** uretir. PCI DSS Req 11.3.2 ASV scan ve Req 11.4 pentest
**yerine gecmez** — onlar dis-makam/gated. Kit onlari kapatmaz; sadece kod-icine
sizmis sorunlari erken yakalar.

## Guvenlik & guven
Public ve [MIT](LICENSE) lisansli, yani **herkes forklayip degistirebilir** (skill'ler dahil —
onlar AI talimatidir). **Tek resmi repo** `github.com/boraeresici/security-audit-kit`;
`bootstrap.sh` varsayilan olarak oraya bakar, bir fork'tan kurmak icin `KIT_REPO`'yu *bilerek*
override etmen gerekir. Kit **ic kanit uretir, garanti yok**. Bir tag/SHA pinle, **skill'leri
calistirmadan once incele**, update'te diff'i gozden gecir. Tam guven modeli, tedarik-zinciri
rehberi ve zafiyet bildirimi: [SECURITY.md](SECURITY.md).

## Lisans
[MIT](LICENSE) — [studiobinary.co](https://studiobinary.co) tarafindan gelistirildi.
