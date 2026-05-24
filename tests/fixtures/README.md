# Synthetic attack fixtures

Each YAML file describes a synthetic PR whose metadata carries a prompt
injection payload. They are loaded by `tests/test_fixtures.py` and run
through the engine end-to-end.

Schema:

```yaml
description: "Short, human-readable explanation of the attack"
target: "fixtures/<filename>"
expect_verdict: pass | warn | fail
expect_rule_ids: ["..."]      # at least one of these must fire
inputs:
  - surface: branch_name | pr_title | pr_body | commit_message | file_name | ...
    text: "the untrusted text"
```

To add a fixture: drop a new YAML file into this folder. The test loader
picks it up automatically.
