"""Tests for the rule pack loader.

The theme running through these is fail-closed. Ward is a security gate, so
every path that would leave it scanning with no rules has to raise rather
than quietly return an empty pack and report PASS on everything.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ward.cli import app
from ward.core.models import Severity
from ward.core.rules import RulePack, RulePackError, load_rule_pack

runner = CliRunner()

VALID_RULE = """
- id: test.example
  category: instruction_override
  severity: high
  description: "Test rule"
  patterns:
    - '(?i)banana protocol'
  surfaces: [pr_body]
  remediation: "Reject it"
"""


def _write_pack(directory: Path, name: str = "rules.yaml", body: str = VALID_RULE) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(body, encoding="utf-8")
    return directory


# --- bundled pack -----------------------------------------------------------


def test_bundled_pack_loads_and_is_not_empty():
    pack = load_rule_pack()
    assert isinstance(pack, RulePack)
    assert pack.rules, "the bundled pack must never load empty"


def test_bundled_pack_has_unique_rule_ids():
    ids = [r.id for r in load_rule_pack().rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids break `ward explain` and suppression"


def test_bundled_rules_are_well_formed():
    for rule in load_rule_pack().rules:
        assert rule.id and rule.category and rule.description
        assert rule.patterns, f"{rule.id} has no patterns"
        assert isinstance(rule.severity, Severity)


# --- fail-closed behaviour --------------------------------------------------


def test_missing_directory_raises_rather_than_loading_empty(tmp_path: Path):
    with pytest.raises(RulePackError, match="does not exist"):
        load_rule_pack(tmp_path / "nope")


def test_path_that_is_a_file_raises(tmp_path: Path):
    target = tmp_path / "rules.yaml"
    target.write_text(VALID_RULE, encoding="utf-8")
    with pytest.raises(RulePackError, match="not a directory"):
        load_rule_pack(target)


def test_directory_with_no_rule_files_raises(tmp_path: Path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(RulePackError, match=r"no \.yaml/\.yml files"):
        load_rule_pack(tmp_path / "empty")


def test_directory_of_empty_yaml_files_raises(tmp_path: Path):
    pack_dir = _write_pack(tmp_path / "pack", body="[]\n")
    with pytest.raises(RulePackError, match="empty rule pack"):
        load_rule_pack(pack_dir)


def test_duplicate_rule_ids_raise(tmp_path: Path):
    pack_dir = _write_pack(tmp_path / "pack", body=VALID_RULE + VALID_RULE)
    with pytest.raises(RulePackError, match="Duplicate rule id"):
        load_rule_pack(pack_dir)


def test_duplicate_ids_across_files_raise(tmp_path: Path):
    pack_dir = _write_pack(tmp_path / "pack", name="a.yaml")
    _write_pack(pack_dir, name="b.yaml")
    with pytest.raises(RulePackError, match="Duplicate rule id"):
        load_rule_pack(pack_dir)


# --- happy path for custom packs -------------------------------------------


def test_custom_pack_loads(tmp_path: Path):
    pack = load_rule_pack(_write_pack(tmp_path / "pack"))
    assert [r.id for r in pack.rules] == ["test.example"]
    assert pack.by_id("test.example") is not None
    assert pack.by_category("instruction_override")


def test_yml_extension_is_accepted(tmp_path: Path):
    """A directory of .yml rules used to load as an empty pack, silently."""
    pack = load_rule_pack(_write_pack(tmp_path / "pack", name="rules.yml"))
    assert [r.id for r in pack.rules] == ["test.example"]


def test_rule_applies_to_declared_surface_only(tmp_path: Path):
    rule = load_rule_pack(_write_pack(tmp_path / "pack")).rules[0]
    assert rule.applies_to("pr_body")
    assert not rule.applies_to("branch_name")


def test_rule_with_no_surfaces_applies_everywhere(tmp_path: Path):
    body = VALID_RULE.replace("  surfaces: [pr_body]\n", "")
    rule = load_rule_pack(_write_pack(tmp_path / "pack", body=body)).rules[0]
    for surface in ("pr_body", "branch_name", "commit_message"):
        assert rule.applies_to(surface)


# --- malformed rule files ---------------------------------------------------


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("- id: x\n  category: c\n  severity: high\n", "missing required field"),
        (
            "- id: x\n  category: c\n  severity: nope\n  description: d\n  patterns: ['a']\n",
            "nope",
        ),
        (
            "- id: x\n  category: c\n  severity: high\n  description: d\n  patterns: []\n",
            "non-empty list",
        ),
        (
            "- id: x\n  category: c\n  severity: high\n  description: d\n"
            "  patterns: ['a']\n  surfaces: nope\n",
            "must be a list",
        ),
        (
            "- id: x\n  category: c\n  severity: high\n  description: d\n"
            "  patterns: ['a']\n  references: nope\n",
            "must be a list",
        ),
    ],
)
def test_malformed_rule_raises(tmp_path: Path, body: str, match: str):
    pack_dir = _write_pack(tmp_path / "pack", body=body)
    with pytest.raises(ValueError, match=match):
        load_rule_pack(pack_dir)


def test_non_list_yaml_raises(tmp_path: Path):
    pack_dir = _write_pack(tmp_path / "pack", body="not: a list\n")
    with pytest.raises(ValueError, match="must contain a YAML list"):
        load_rule_pack(pack_dir)


# --- CLI wiring -------------------------------------------------------------


def test_cli_exits_2_on_missing_rule_pack(tmp_path: Path):
    """Exit 2, not 0. Exit 0 would be a green CI tick with nothing scanned."""
    result = runner.invoke(app, ["scan-branch", "fix/typo", "--rule-pack", str(tmp_path / "nope")])
    assert result.exit_code == 2
    assert "Rule pack error" in result.output


def test_cli_exits_2_on_empty_rule_pack(tmp_path: Path):
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    result = runner.invoke(app, ["scan-branch", "fix/typo", "--rule-pack", str(pack_dir)])
    assert result.exit_code == 2
    assert "Rule pack error" in result.output


def test_cli_accepts_a_valid_custom_pack(tmp_path: Path):
    pack_dir = _write_pack(tmp_path / "pack")
    result = runner.invoke(
        app,
        ["scan-stdin", "--surface", "pr_body", "--rule-pack", str(pack_dir), "--format", "json"],
        input="activate the banana protocol",
    )
    assert result.exit_code == 2
    assert "test.example" in result.output
