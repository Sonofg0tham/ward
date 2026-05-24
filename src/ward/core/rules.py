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
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import cast

import yaml

from .models import Severity, Surface


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


def load_rule_pack(custom_dir: Path | None = None) -> RulePack:
    """Load all rule YAML files from the bundled pack or a custom directory."""
    rules: list[Rule] = []
    if custom_dir is not None:
        for yaml_path in sorted(custom_dir.glob("*.yaml")):
            for raw in _load_yaml_file(yaml_path):
                rules.append(_build_rule(raw, str(yaml_path)))
    else:
        package = resources.files("ward.rules")
        for resource in sorted(package.iterdir(), key=lambda r: r.name):
            if not resource.name.endswith(".yaml"):
                continue
            with resources.as_file(resource) as path:
                for raw in _load_yaml_file(path):
                    rules.append(_build_rule(raw, resource.name))
    return RulePack(rules=tuple(rules))
