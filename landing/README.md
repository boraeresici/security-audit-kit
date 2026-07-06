# landing/ — static landing page (Cloudflare Pages)

Single-page static site for security-audit-kit. No build step, no dependencies,
**zero external requests** — inline CSS/JS, self-hosted fonts (`fonts/`, woff2 latin
subsets of IBM Plex Sans + IBM Plex Mono, ~70 KB total).

## Deploy (Cloudflare Pages, GitHub integration)

- **Framework preset:** None
- **Build command:** *(empty)*
- **Build output directory:** `landing`
- Production branch: `main` — every push to `main` redeploys automatically.

`_headers` ships strict security headers (CSP, X-Frame-Options, nosniff) — CF Pages
picks it up from the output directory automatically.

## Keep in sync

The comparison table mirrors [docs/compare/aikido-semgrep.md](../docs/compare/aikido-semgrep.md).
When that file or the kit version changes, update the table, the version strings
(hero terminal, footer) and the "Last updated" line in the compare section.

This directory is a website, not part of the kit runtime — `scan.sh`, hooks and
skills never read it.
