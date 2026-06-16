## Summary
<!-- What does this change and why? -->

## Checklist
- [ ] `shellcheck scan.sh install.sh bootstrap.sh hooks/pre-commit hooks/pre-push` passes
- [ ] `bash scan.sh doctor` runs clean
- [ ] Updated **both** `README.md` and `README-tr.md` if behavior changed
- [ ] Added a `CHANGELOG.md` entry
- [ ] Any bumped tool is pinned (Python: version; docker: immutable digest) and reflected in `doctor`
- [ ] No `curl | bash`; portable to bash 3.2 (no associative arrays / `mapfile`)
