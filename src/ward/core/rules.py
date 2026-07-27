"""Rule pack loader.

Rules live in ``src/ward/rules/*.yaml`` and are bundled with the wheel. A
custom rule pack directory can be supplied via the CLI ``--rule-pack`` flag.

The on-disk format is intentionally small. Each YAML file contains a list
of rule dicts:

```yaml
- id: io.ignore_previous
  category: instruction_override
  severity: high
  description: "Classic 'ignore previous instructions' injection"
  patterns:
    - '(?i)ignore (?:all )?(?:previous|prior|above) instructions'
  surfaces: [branch_name, commit_message, pr_title, pr_body, file_content]
  remediation: "Reject the metadata, contact the PR author"
  references:
    - "https://genai.owasp.org/asi/asi01-goal-hijack"
```
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import cast

import yaml

from .models import Severity, Surface


class RulePackError(ValueError):
    """Raised when a rule pack cannot be loaded or would load empty.

    Subclasses ``ValueError`` so existing callers that catch ``ValueError``
    around rule parsing keep working.
    """


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    description: str
    patterns: tuple[re.Pattern[str], ...]
    surfaces: frozenset[Surface]
    remediation: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)

    def applies_to(self, surface: Surface) -> bool:
        return not self.surfaces or surface in self.surfaces


@dataclass(frozen=True)
class RulePack:
    rules: tuple[Rule, ...]

    def by_category(self, category: str) -> tuple[Rule, ...]:
        return tuple(r for r in self.rules if r.category == category)

    def by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


def _load_yaml_file(path: Path) -> list[dict[str, object]]:
    with path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or []
    if not isinstance(loaded, list):
        raise ValueError(f"Rule file {path} must contain a YAML list")
    return cast(list[dict[str, object]], loaded)


def _build_rule(raw: dict[str, object], source: str) -> Rule:
    try:
        rule_id = str(raw["id"])
        category = str(raw["category"])
        severity = Severity(str(raw["severity"]))
        description = str(raw["description"])
        pattern_list = raw.get("patterns") or []
        if not isinstance(pattern_list, list) or not pattern_list:
            raise ValueError(f"Rule {rule_id} in {source}: 'patterns' must be a non-empty list")
        patterns = tuple(re.compile(str(p), re.MULTILINE) for p in pattern_list)
        surfaces_raw = raw.get("surfaces") or []
        if not isinstance(surfaces_raw, list):
            raise ValueError(f"Rule {rule_id} in {source}: 'surfaces' must be a list")
        surfaces = frozenset(cast(Surface, str(s)) for s in surfaces_raw)
        remediation = str(raw.get("remediation", ""))
        refs_raw = raw.get("references") or []
        if not isinstance(refs_raw, list):
            raise ValueError(f"Rule {rule_id} in {source}: 'references' must be a list")
        references = tuple(str(r) for r in refs_raw)
    except KeyError as exc:
        raise ValueError(f"Rule in {source} missing required field {exc}") from exc

    return Rule(
        id=rule_id,
        category=category,
        severity=severity,
        description=description,
        patterns=patterns,
        surfaces=surfaces,
        remediation=remediation,
        references=references,
    )


@contextmanager
def _as_rule_pack_error(source: str) -> Iterator[None]:
    """Funnel every load failure into RulePackError.

    Only ``RulePackError`` is special-cased by the CLI into exit 2. Malformed
    YAML, an uncompilable regex, or an unreadable file used to escape as
    ``yaml.YAMLError`` / ``re.error`` / ``OSError`` and exit 1 - which the
    GitHub Action reads as WARN and passes the job. A rule pack that will not
    load is a broken gate however it failed to load.
    """
    try:
        yield
    except RulePackError:
        raise
    except (ValueError, yaml.YAMLError, re.error, OSError) as exc:
        raise RulePackError(f"Could not load {source}: {exc}") from exc


def _check_no_duplicate_ids(rules: list[Rule], source: str) -> None:
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule in rules:
        if rule.id in seen and rule.id not in duplicates:
            duplicates.append(rule.id)
        seen.add(rule.id)
    if duplicates:
        raise RulePackError(
            f"Duplicate rule id(s) in {source}: {', '.join(sorted(duplicates))}. "
            "Rule ids must be unique - `ward explain <id>` and suppression "
            "directives both resolve by id."
        )


def load_rule_pack(custom_dir: Path | None = None) -> RulePack:
    """Load all rule YAML files from the bundled pack or a custom directory.

    A rule pack that loads zero rules is always an error, never a silent
    empty pack. Ward is a security gate: scanning with no rules would report
    PASS on everything, so a mistyped ``--rule-pack`` path has to be loud.

    Raises:
        RulePackError: if ``custom_dir`` is missing, is not a directory,
            holds no rule files, contains duplicate rule ids, or the pack
            otherwise resolves to zero rules.
    """
    rules: list[Rule] = []
    if custom_dir is not None:
        if not custom_dir.exists():
            raise RulePackError(f"Rule pack directory does not exist: {custom_dir}")
        if not custom_dir.is_dir():
            raise RulePackError(f"Rule pack path is not a directory: {custom_dir}")
        # Accept .yml as well as .yaml - silently ignoring a directory of
        # .yml rules was the same fail-open trap as a missing directory.
        yaml_paths = sorted(
            (p for p in custom_dir.iterdir() if p.suffix in (".yaml", ".yml")),
            key=lambda p: p.name,
        )
        if not yaml_paths:
            raise RulePackError(f"Rule pack directory contains no .yaml/.yml files: {custom_dir}")
        source = str(custom_dir)
        with _as_rule_pack_error(source):
            for yaml_path in yaml_paths:
                for raw in _load_yaml_file(yaml_path):
                    rules.append(_build_rule(raw, str(yaml_path)))
    else:
        source = "the bundled rule pack"
        with _as_rule_pack_error(source):
            package = resources.files("ward.rules")
            for resource in sorted(package.iterdir(), key=lambda r: r.name):
                if not resource.name.endswith(".yaml"):
                    continue
                with resources.as_file(resource) as path:
                    for raw in _load_yaml_file(path):
                        rules.append(_build_rule(raw, resource.name))

    if not rules:
        raise RulePackError(
            f"No rules loaded from {source}. Refusing to scan with an empty rule "
            "pack - every input would report PASS."
        )
    _check_no_duplicate_ids(rules, source)
    return RulePack(rules=tuple(rules))
