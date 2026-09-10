"""Unit tests for lib/pkgcheck.py

Covers: parse(), _npm_spec(), _pypi_spec(), classify(), _command_from_payload().
Stdlib + pytest only — no external dependencies.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))

from pkgcheck import (  # noqa: E402
    _command_from_payload,
    _npm_spec,
    _pypi_spec,
    classify,
    parse,
)


# ---------------------------------------------------------------------------
# parse() — command-line → install-target extraction
# ---------------------------------------------------------------------------


class TestParse:
    """Each call returns a list of (ecosystem, package, version) tuples."""

    # 1. npm exact version
    def test_npm_exact_version(self):
        assert parse("npm install lodash@4.17.21") == [("npm", "lodash", "4.17.21")]

    # 2. pip exact version
    def test_pip_exact_version(self):
        assert parse("pip install requests==2.32.3") == [("pypi", "requests", "2.32.3")]

    # 3. pip range version → version string empty (not exact)
    def test_pip_range_version_is_empty(self):
        assert parse("pip install django>=5") == [("pypi", "django", "")]

    # 4. bare `npm install` → lockfile install, nothing to extract
    def test_npm_install_no_package(self):
        assert parse("npm install") == []

    # 5. git clone → not an install command
    def test_git_clone_ignored(self):
        assert parse("git clone https://example.com") == []

    # 6. pip install -r requirements.txt → -r flag skips the file argument
    def test_pip_requirements_file_skipped(self):
        assert parse("pip install -r requirements.txt") == []

    # 7. local path → unverifiable
    def test_pip_local_path_unverifiable(self):
        result = parse("pip install ./local-pkg")
        assert result == [("unverifiable", "./local-pkg", "local path or archive")]

    # 8. VCS URL → unverifiable
    def test_pip_vcs_url_unverifiable(self):
        result = parse("pip install git+https://github.com/foo/bar")
        assert len(result) == 1
        assert result[0][0] == "unverifiable"
        assert "git+https://github.com/foo/bar" in result[0][1]

    # 9. chained commands → both ecosystems extracted
    def test_chained_npm_and_pip(self):
        result = parse("npm install pkg1 && pip install pkg2")
        assert ("npm", "pkg1", "") in result
        assert ("pypi", "pkg2", "") in result
        assert len(result) == 2

    # 10. sudo is stripped before parsing
    def test_sudo_stripped(self):
        assert parse("sudo pip install requests") == [("pypi", "requests", "")]

    # 11. `python -m pip` is recognized
    def test_python_m_pip(self):
        assert parse("python -m pip install flask") == [("pypi", "flask", "")]

    # 12. `uv pip install` is recognized
    def test_uv_pip_install(self):
        assert parse("uv pip install django==5.0") == [("pypi", "django", "5.0")]

    # 13. pnpm add
    def test_pnpm_add(self):
        assert parse("pnpm add express@4.18.2") == [("npm", "express", "4.18.2")]

    # 14. extras in pip spec are stripped (pkg[extra]==1.0 → pkg)
    def test_pip_extras_stripped(self):
        result = parse("pip install 'pkg[extra]==1.0'")
        assert result == [("pypi", "pkg", "1.0")]

    # 15. scoped npm packages
    def test_npm_scoped_package(self):
        assert parse("npm install @scope/pkg@1.2.3") == [("npm", "@scope/pkg", "1.2.3")]

    # Additional edge cases
    def test_yarn_add(self):
        assert parse("yarn add express@4.18.2") == [("npm", "express", "4.18.2")]

    def test_bun_add(self):
        assert parse("bun add lodash@4.17.21") == [("npm", "lodash", "4.17.21")]

    def test_poetry_add(self):
        assert parse("poetry add requests==2.32.3") == [("pypi", "requests", "2.32.3")]

    def test_pip3_install(self):
        assert parse("pip3 install flask") == [("pypi", "flask", "")]

    def test_pipx_install(self):
        assert parse("pipx install black==24.0.0") == [("pypi", "black", "24.0.0")]

    def test_empty_command(self):
        assert parse("") == []

    def test_env_var_prefix_stripped(self):
        result = parse("FOO=bar pip install requests==2.32.3")
        assert result == [("pypi", "requests", "2.32.3")]

    def test_pip_editable_skipped(self):
        assert parse("pip install -e ./local") == []

    def test_pip_constraint_skipped(self):
        assert parse("pip install -c constraints.txt") == []

    def test_pip_constraint_long_flag_skipped(self):
        assert parse("pip install --constraint constraints.txt") == []

    def test_pip_requirement_long_flag_skipped(self):
        assert parse("pip install --requirement requirements.txt") == []

    def test_archive_unverifiable(self):
        result = parse("pip install package-1.0.tar.gz")
        assert result == [("unverifiable", "package-1.0.tar.gz", "local path or archive")]

    def test_url_unverifiable(self):
        result = parse("pip install https://example.com/pkg.whl")
        assert len(result) == 1
        assert result[0][0] == "unverifiable"

    def test_npm_i_alias(self):
        assert parse("npm i lodash@4.17.21") == [("npm", "lodash", "4.17.21")]

    def test_pnpm_i_alias(self):
        assert parse("pnpm i express") == [("npm", "express", "")]

    def test_python3_m_pip(self):
        assert parse("python3 -m pip install flask==3.0") == [("pypi", "flask", "3.0")]


# ---------------------------------------------------------------------------
# parse() — deduplication
# ---------------------------------------------------------------------------


class TestParseDedup:
    # 32. duplicate packages across segments are deduplicated
    def test_dedup_across_segments(self):
        result = parse("pip install foo && pip install foo")
        assert result == [("pypi", "foo", "")]

    def test_dedup_different_versions_kept(self):
        # Different (eco, name, ver) tuples are distinct entries.
        result = parse("pip install foo==1.0 && pip install foo==2.0")
        assert len(result) == 2
        assert ("pypi", "foo", "1.0") in result
        assert ("pypi", "foo", "2.0") in result


# ---------------------------------------------------------------------------
# _npm_spec() — npm token → (name, version)
# ---------------------------------------------------------------------------


class TestNpmSpec:
    @pytest.mark.parametrize(
        "token, expected",
        [
            # 16. exact version
            ("lodash@4.17.21", ("lodash", "4.17.21")),
            # 17. scoped package with version
            ("@scope/pkg@1.2.3", ("@scope/pkg", "1.2.3")),
            # 18. bare name, no version
            ("lodash", ("lodash", "")),
            # scoped package without version — @scope/pkg has rfind("@")==0, so no split
            ("@scope/pkg", ("@scope/pkg", "")),
            # range version → empty (not exact)
            ("lodash@^4.0.0", ("lodash", "")),
            # tilde range → empty
            ("lodash@~4.17.0", ("lodash", "")),
            # pre-release with hyphen is valid
            ("pkg@1.0.0-beta.1", ("pkg", "1.0.0-beta.1")),
        ],
    )
    def test_npm_spec(self, token, expected):
        assert _npm_spec(token) == expected


# ---------------------------------------------------------------------------
# _pypi_spec() — pip token → (name, version)
# ---------------------------------------------------------------------------


class TestPypiSpec:
    @pytest.mark.parametrize(
        "token, expected",
        [
            # 19. exact version
            ("requests==2.32.3", ("requests", "2.32.3")),
            # 20. range version → empty
            ("django>=5", ("django", "")),
            # 21. extras stripped
            ("pkg[extra]==1.0", ("pkg", "1.0")),
            # bare name
            ("flask", ("flask", "")),
            # != operator → empty
            ("pkg!=1.0", ("pkg", "")),
            # ~= compatible release → empty
            ("pkg~=2.0", ("pkg", "")),
            # < operator → empty
            ("pkg<3.0", ("pkg", "")),
            # > operator → empty
            ("pkg>1.0", ("pkg", "")),
            # <= operator → empty
            ("pkg<=2.0", ("pkg", "")),
            # multiple extras stripped
            ("pkg[extra1,extra2]==1.0", ("pkg", "1.0")),
            # version with pre-release
            ("pkg==1.0a1", ("pkg", "1.0a1")),
            # version with post release
            ("pkg==1.0.post1", ("pkg", "1.0.post1")),
        ],
    )
    def test_pypi_spec(self, token, expected):
        assert _pypi_spec(token) == expected


# ---------------------------------------------------------------------------
# classify() — guarddog JSON → verdict
# ---------------------------------------------------------------------------


class TestClassify:
    # 22. clean — no results, no errors
    def test_clean(self):
        verdict, code, detail = classify({"results": {}, "errors": {}})
        assert verdict == "CLEAN"
        assert code == 0
        assert "no rules fired" in detail

    # 23. block on typosquatting
    def test_block_typosquatting(self):
        verdict, code, detail = classify({"results": {"typosquatting": 1}, "errors": {}})
        assert verdict == "BLOCK"
        assert code == 1
        assert "typosquatting" in detail

    # 24. capability rule → NOTE, not block
    def test_note_capability(self):
        verdict, code, detail = classify({"results": {"capability-network": 1}, "errors": {}})
        assert verdict == "NOTE"
        assert code == 0
        assert "capability-network" in detail

    # 25. errors present + results None → INDETERMINATE
    def test_indeterminate_on_errors(self):
        verdict, code, detail = classify({"results": None, "errors": {"download": "404"}})
        assert verdict == "INDETERMINATE"
        assert code == 2
        assert "404" in detail

    # 26. block_extra adds to the block set; existing block rule still blocks
    def test_block_extra_does_not_remove_existing_block(self):
        verdict, code, _ = classify(
            {"results": {"typosquatting": 1}, "errors": {}},
            block_extra=("capability-network",),
        )
        assert verdict == "BLOCK"
        assert code == 1

    # 27. report_extra demotes a block rule to NOTE
    def test_report_extra_demotes_to_note(self):
        verdict, code, detail = classify(
            {"results": {"typosquatting": 1}, "errors": {}},
            report_extra=("typosquatting",),
        )
        assert verdict == "NOTE"
        assert code == 0
        assert "typosquatting" in detail

    # 28. non-dict input → INDETERMINATE
    def test_non_dict_input(self):
        verdict, code, _ = classify("not a dict")
        assert verdict == "INDETERMINATE"
        assert code == 2

    # results is None with empty errors → INDETERMINATE (guarddog silent failure)
    def test_results_none_no_errors(self):
        verdict, code, detail = classify({"results": None, "errors": {}})
        assert verdict == "INDETERMINATE"
        assert code == 2
        assert "NOT SCANNED" in detail

    # block_extra promotes a note rule to block
    def test_block_extra_promotes_note_to_block(self):
        verdict, code, _ = classify(
            {"results": {"capability-network": 1}, "errors": {}},
            block_extra=("capability-network",),
        )
        assert verdict == "BLOCK"
        assert code == 1

    # report_extra only demotes — does not affect other block rules
    def test_report_extra_does_not_affect_other_rules(self):
        verdict, code, _ = classify(
            {"results": {"typosquatting": 1, "capability-network": 1}, "errors": {}},
            report_extra=("capability-network",),
        )
        # typosquatting is still a block rule; capability-network was already not blocking
        assert verdict == "BLOCK"
        assert code == 1

    # zero-hit rule is not "fired"
    def test_zero_hit_rule_not_fired(self):
        verdict, code, _ = classify({"results": {"typosquatting": 0}, "errors": {}})
        assert verdict == "CLEAN"
        assert code == 0

    # list input → INDETERMINATE
    def test_list_input(self):
        verdict, code, _ = classify([1, 2, 3])
        assert verdict == "INDETERMINATE"
        assert code == 2

    # None input → INDETERMINATE
    def test_none_input(self):
        verdict, code, _ = classify(None)
        assert verdict == "INDETERMINATE"
        assert code == 2


# ---------------------------------------------------------------------------
# _command_from_payload() — agent hook JSON → command string
# ---------------------------------------------------------------------------


class TestCommandFromPayload:
    # 29. tool_input.command
    def test_tool_input_command(self):
        doc = {"tool_input": {"command": "npm install foo"}}
        assert _command_from_payload(doc) == "npm install foo"

    # 30. input.command (alternative key path)
    def test_input_command(self):
        doc = {"input": {"command": "pip install bar"}}
        assert _command_from_payload(doc) == "pip install bar"

    # 31. empty dict → empty string
    def test_empty_dict(self):
        assert _command_from_payload({}) == ""

    # tool_input.cmd (alternative key)
    def test_tool_input_cmd(self):
        doc = {"tool_input": {"cmd": "npm install baz"}}
        assert _command_from_payload(doc) == "npm install baz"

    # input.cmd (alternative key)
    def test_input_cmd(self):
        doc = {"input": {"cmd": "pip install qux"}}
        assert _command_from_payload(doc) == "pip install qux"

    # toolCall.args.CommandLine (deep path)
    def test_tool_call_args_command_line(self):
        doc = {"toolCall": {"args": {"CommandLine": "pip install deep"}}}
        assert _command_from_payload(doc) == "pip install deep"

    # params.command
    def test_params_command(self):
        doc = {"params": {"command": "npm install via-params"}}
        assert _command_from_payload(doc) == "npm install via-params"

    # non-dict → empty string
    def test_non_dict_returns_empty(self):
        assert _command_from_payload("not a dict") == ""
        assert _command_from_payload(None) == ""
        assert _command_from_payload(42) == ""

    # whitespace-only command → empty string
    def test_whitespace_only_command(self):
        doc = {"tool_input": {"command": "   "}}
        assert _command_from_payload(doc) == ""

    # priority: tool_input.command is checked before input.command
    def test_priority_tool_input_over_input(self):
        doc = {
            "tool_input": {"command": "first"},
            "input": {"command": "second"},
        }
        assert _command_from_payload(doc) == "first"
