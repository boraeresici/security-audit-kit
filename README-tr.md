# security-audit-kit — tasinabilir yerel guvenlik tarama

> 🌐 **English:** [README.md](README.md) · **Türkçe:** bu dosya

CI'a (ve faturasina) bagimli olmadan, **herhangi bir git repo'sunda** yerel
guvenlik taramasi koşturan, hook'larla otomatik tetikleyen ve bulgu triyajini
bir Claude skill'ine baglayan kendi-kendine yeten kit.

Kapsanan boyutlar: **sir** (gitleaks), **SAST** (semgrep), **bagimlilik CVE**
(pip-audit + pnpm/yarn/npm), **IaC misconfig** (checkov), **container/fs**
(trivy), **SBOM** (syft). Eksik toolchain olan boyut otomatik atlanir.

Bunlarin ustune iki Claude skill'i yargi katmani ekler: **`sec-triage`** (ham
tarama -> gercek/FP karari -> fix/allowlist) ve **`sec-sast-deep`** (semgrep'in
pattern'le goremedigi *semantik* aciklar: yatay authz/IDOR, dikey authz/eksik-rol,
business-logic — cagri-yolu izleyerek). Ikincisi `scan.sh`'a girmez (yargi, script
degil); periyodik/cutover-oncesi/yeni-endpoint sonrasi Claude'da kosulur.

## Baska projeye kurmak (paket gibi)

```bash
# 1) Bu klasoru hedef repoya kopyala
cp -R tools/security-audit-kit /yeni/proje/tools/

# 2) Hedef repo kokunden tek komut
cd /yeni/proje && bash tools/security-audit-kit/install.sh
```

`install.sh`: prerequisite'leri raporlar -> `core.hooksPath`'i kitin hooks
klasorune isaretler -> `sec-triage` + `sec-sast-deep` skill'lerini
`.claude/skills/`'e kopyalar. Idempotent, tekrar kosulabilir.

## Kitin kendi repo'sundan tek-komut kurulum (pinli)

Kit kendi git repo'sundaysa, `bootstrap.sh` onu **pinli bir ref**'te ceker ve
projenin `tools/security-audit-kit/`'ine vendor'lar, sonra `install.sh`'i kosar.
Hedef repo kokunden calistir:

```bash
# 1) Bootstrap scriptini indir ve ONCE OKU (shell'e pipe etme):
curl -fsSL https://raw.githubusercontent.com/boraeresici/security-audit-kit/main/bootstrap.sh \
  -o bootstrap.sh && less bootstrap.sh
# 2) Bir tag'e pinleyerek kos:
bash bootstrap.sh v1.0.0
bash bootstrap.sh v1.0.0 --scan        # kurulumdan sonra tam tarama da kos
```

> `bootstrap.sh` icindeki `KIT_REPO` varsayilan olarak bu repo'ya isaret eder. Fork'tan
> vendor'lamak icin override et: `KIT_REPO=https://… bash bootstrap.sh v1.0.0`.

Neden bu bicim (kitin kendi felsefesiyle tutarli):
- **`curl | bash` YOK.** Bu bir *guvenlik* aracidir — indir, gozden gecir, sonra
  calistir. Uzaktan scripti dogrudan shell'e pipe etmek tam da kitin uyardigi
  anti-pattern'dir.
- **Pinleme pratikte zorunlu.** Hareketli ref (`main`) "CI ile drift yok" vaadini
  bozar; tag/SHA vermezsen bootstrap uyarir. `.kit-version` (ref + cozulen SHA)
  yazar — commit'lersen tum takim tek pinli surumu paylasir.
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
   # vendored version : v1.0.0
   # latest tag       : v1.1.0
   # !! UPDATE AVAILABLE -> bash tools/security-audit-kit/bootstrap.sh v1.1.0
   ```
   Cikis kodu: `0` = guncel, `1` = guncelleme var — periyodik kontrol veya bir
   `make` hedefine baglanabilir.
2. **Kit repo'sunun release'lerini izle** (GitHub Watch → Custom → Releases): yeni
   tag cikinca bildirim alirsin.

**Guncellemeyi uygula** (idempotent — vendor kopyayi ust-yazar,
`.security-audit.conf`'unu korur):
```bash
bash tools/security-audit-kit/bootstrap.sh v1.1.0   # yeni pinli tag
git diff -- tools/security-audit-kit                 # ne degisti, gozden gecir
git add tools/security-audit-kit && git commit -m "chore(sec): security-audit-kit v1.1.0'e yukselt"
```
Commit'lenen `.kit-version` (ref + SHA) takimin hangi pinli surumu kullandiginin
ortak kaydidir ve `--check`'in bir sonraki sefer karsilastiracagi referanstir.

## Gereksinimler (hangisi yoksa o boyut atlanir)
- **docker** — gitleaks / trivy / syft (pinli image, kurulum yok)
- **uvx veya pipx** — semgrep / checkov / pip-audit (kurulum yok, on-demand)
- **pnpm / yarn / npm** — JS dep audit (projede hangisi varsa)

Hicbir tool'u kalici kurmana gerek yok; surumler pinli (CI ile drift yok).

## Kullanim

```
bash tools/security-audit-kit/scan.sh all        # tam (PR oncesi)
bash tools/security-audit-kit/scan.sh fast       # secret + deps (paket-yukleme)
bash tools/security-audit-kit/scan.sh secret|sast|deps|iac|container|sbom
```

Otomatik tetik (install sonrasi):
- **pre-commit** — bagimlilik manifesti stage edilirse `scan.sh fast` (HARD).
- **pre-push** — `scan.sh all` (HARD). PR'dan hemen once.
- Bypass (acil): `SKIP_SECURITY=1 git commit` / `git push --no-verify`.

## Bulgu dongusu (uctan uca)

```
yeni paket  --(pre-commit)-->  scan.sh fast
PR oncesi   --(pre-push)----->  scan.sh all
bulgu       --> Claude'da /sec-triage --> docs/security/scan-findings/findings-YYYY-MM-DD.md
                                          |- FP    -> allowlist (.gitleaks.toml / nosemgrep / .pip-audit-ignore)
                                          |- GERCEK -> fix VEYA takip-listesi entry
```

## Derin (semantik) SAST — `/sec-sast-deep`

`scan.sh sast` (semgrep) **pattern-tabanli**: bilinen kotu-imzayi yakalar.
Authorization ve business-rule aciklari ise koddaki **niyet**e baglidir — pattern
degil **cagri-yolu** meselesi. `sec-sast-deep` skill'i o 3 sinifi Claude ile
derin tarar: yatay authz/IDOR, dikey authz/eksik-rol, business-logic. semgrep'i
**degistirmez, tamamlar**.

- **`scan.sh`'a GIRMEZ** (yargi, script degil); Claude'da `/sec-sast-deep` olarak kosulur.
- **Ne zaman:** cutover-oncesi (faz exit / version bump), yeni authz-yuzeyi sonrasi
  (yeni endpoint/resolver/admin-viewer/4-goz akisi), veya talep uzerine. Her push'ta DEGIL.
- Cikti ayni `sec-triage` akisina baglanir (findings dosyasi + takip-listesi terfi).
- Kaynak/ilham: `github.com/utkusen/sast-skills` (uc-fazli recon->verify->merge);
  kit'in triyaj akisina uyarlandi.

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
yoneticisi auto-detect). Ozellestirme icin proje-basina bir dosya:

1. `install.sh` kurulumda repo kokune **`.security-audit.conf`** olusturur
   (sablon: `security-audit.conf.example`).
2. Degerleri projene gore ayarla ve **repo'ya commit et** (ekip paylasimi):
   ```sh
   : "${SAST_PATHS:=backend frontend}"     # kaynak dizinleri daralt
   : "${TF_DIR:=infra/terraform}"          # terraform dizini
   : "${SEMGREP_CONFIGS:=--config p/python --config p/react ...}"
   ```
3. `scan.sh` bunu otomatik source eder.

**Onculuk:** `env > .security-audit.conf > default`. `:=` formu sayesinde
tek-seferlik override icin env kullan: `SAST_PATHS="lib" bash scan.sh sast`.

Pin'ler de ayni dosyadan: `GITLEAKS_VER` / `TRIVY_VER` / `SYFT_VER`.

## HARD sinir
Bu araclar **ic kanit** uretir. PCI DSS Req 11.3.2 ASV scan ve Req 11.4 pentest
**yerine gecmez** — onlar dis-makam/gated. Kit onlari kapatmaz; sadece kod-icine
sizmis sorunlari erken yakalar.

## Lisans
[MIT](LICENSE) — [studiobinary.io](https://studiobinary.io) tarafindan gelistirildi.
