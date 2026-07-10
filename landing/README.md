# landing/ — static landing page (Cloudflare Pages)

Single-page static site for security-audit-kit. No build step, no dependencies,
**zero external requests** — inline CSS/JS, self-hosted fonts (`fonts/`, woff2 latin
subsets of IBM Plex Sans + IBM Plex Mono, ~70 KB total).

## Deploy (Cloudflare Pages, GitHub integration)

- **Framework preset:** None
- **Build command:** `python3 landing/build.py`
- **Build output directory:** `landing`
- Production branch: `main` — every push to `main` redeploys automatically.

`_headers` ships strict security headers (CSP, X-Frame-Options, nosniff) — CF Pages
picks it up from the output directory automatically.

## Comparison table is generated

`build.py` regenerates the block between the `<!-- compare:start/end -->` markers in
`index.html` from [docs/compare/aikido-semgrep.md](../docs/compare/aikido-semgrep.md)
(the source of truth), and refreshes the kit version + "Last updated" strings from that
doc's header. It runs on every CF Pages deploy, so the published table can never drift
from the doc. If the doc's format changes in a way the parser can't read, the script
exits non-zero and the deploy fails loudly instead of publishing a stale table.

Run it locally after editing the compare doc to keep the committed `index.html` fresh
(optional — the deploy regenerates it anyway):

```bash
python3 landing/build.py
```

This directory is a website, not part of the kit runtime — `scan.sh`, hooks and
skills never read it.
