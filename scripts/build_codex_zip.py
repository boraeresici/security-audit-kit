#!/usr/bin/env python3
"""Build the ZIP submitted to the OpenAI plugin directory (ChatGPT and Codex) — F43b.

The directory takes a ZIP, not a repository path. It is built from the plugin folder (plugin/, R17)
and holds the Codex manifest, the listing icon, the five skills and the licence. Not the scanner, not the
docs, not the test fixtures (some pin known-vulnerable packages on purpose). The plugin folder has
no hooks (the directory does not accept lifecycle hooks); the edit check is the kit's.

The rules checked here are the ones the OpenAI pages state (developers.openai.com/plugins/deploy/
submission, /codex/plugins/build, read 2026-11-20). The build is reproducible: fixed order, fixed
timestamps, so the same commit gives the same bytes.

Usage: python3 scripts/build_codex_zip.py [out.zip]     (default: dist/<name>-codex-<version>.zip)
"""
import json
import os
import re
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "plugin")      # the plugin folder (R17): every packaged path is relative to it
MANIFEST = ".codex-plugin/plugin.json"
EPOCH = (2026, 1, 1, 0, 0, 0)      # fixed: zip entries carry no build time
LIMITS = {"displayName": 30, "shortDescription": 30, "longDescription": 4000, "developerName": 80}
FORBIDDEN = ("hooks/", ".app.json", ".mcp.json", "apps/")


def fail(msg):
    print(f"build_codex_zip: {msg}", file=sys.stderr)
    sys.exit(1)


def icon_ok(path):
    b = open(path, "rb").read()
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return "not a PNG"
    w, h = struct.unpack(">II", b[16:24])
    if w != h or w < 48 or w > 4096:
        return f"{w}x{h}: must be square, 48 to 4096 px"
    if len(b) > 5 * 1024 * 1024:
        return "over 5 MiB"
    return None


def files(m):
    """Every path the package holds, relative to the plugin root."""
    out = [MANIFEST, "LICENSE"]
    for key in ("logo", "composerIcon"):
        out.append(m["interface"][key][2:])     # check() has made sure it starts with ./
    skills = m["skills"].strip("./").rstrip("/")
    for name in sorted(os.listdir(os.path.join(PLUGIN, skills))):
        if os.path.isfile(os.path.join(PLUGIN, skills, name, "SKILL.md")):
            out.append(f"{skills}/{name}/SKILL.md")
    return sorted(set(out))


def check(m):
    claude = json.load(open(os.path.join(PLUGIN, ".claude-plugin/plugin.json")))
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", m.get("name", "")) or len(m["name"]) > 64:
        fail(f"name {m.get('name')!r}: lowercase letters, digits and single hyphens, at most 64")
    if m.get("version") != claude.get("version"):
        fail(f"version {m.get('version')} != .claude-plugin/plugin.json {claude.get('version')}: bump both")
    if not m.get("description") or len(m["description"]) > 4000:
        fail("description: required, at most 4000 characters")
    if not (m.get("author") or {}).get("name"):
        fail("author.name is required")
    if m.get("skills") != "./skills/":
        fail('skills must be "./skills/"')
    if "hooks" in m:
        fail("the manifest names hooks: the directory does not accept lifecycle hooks")
    i = m.get("interface") or {}
    for k, n in LIMITS.items():
        if not i.get(k) or len(i[k]) > n:
            fail(f"interface.{k}: required, at most {n} characters")
    # The upload refuses a manifest without it ("must not be empty when provided"), although its
    # message suggests omitting it. A dashboard category title, e.g. "Developer Tools".
    if not isinstance(i.get("category"), str) or not i["category"].strip() or len(i["category"]) > 80:
        fail("interface.category: required, a category title such as \"Developer Tools\"")
    # Listed as optional for skills-only ZIPs in the docs, but the upload asks for all four (2026-11-22).
    for k in ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"):
        if not isinstance(i.get(k), str) or not re.fullmatch(r"https://[^\s\"<>]+", i[k]):
            fail(f"interface.{k}: required, an https:// URL")
    caps = i.get("capabilities")
    if not isinstance(caps, list) or len(caps) > 20 or any(len(c) > 120 for c in caps):
        fail("interface.capabilities: a list of at most 20 items of at most 120 characters")
    prompts = i.get("defaultPrompt") or []
    if len(prompts) > 3 or any(len(p) > 128 for p in prompts):
        fail("interface.defaultPrompt: at most 3 items of at most 128 characters")
    for k in ("logo", "composerIcon"):
        v = i.get(k) or ""
        if not v.startswith("./") or ".." in v.split("/"):
            fail(f"interface.{k}: a ./ path inside the plugin")
        why = icon_ok(os.path.join(PLUGIN, v[2:]))
        if why:
            fail(f"interface.{k} {v}: {why}")


def main():
    m = json.load(open(os.path.join(PLUGIN, MANIFEST)))
    check(m)
    names = files(m)
    bad = [n for n in names if n.startswith(FORBIDDEN) or n.endswith(FORBIDDEN)]
    if bad:
        fail(f"would package what the directory refuses: {bad}")
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist", f"{m['name']}-codex-{m['version']}.zip")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in names:
            info = zipfile.ZipInfo(n, EPOCH)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, open(os.path.join(PLUGIN, n), "rb").read())
    print(f"build_codex_zip: wrote {out} ({len(names)} files)")
    for n in names:
        print(f"  {n}")


if __name__ == "__main__":
    main()
