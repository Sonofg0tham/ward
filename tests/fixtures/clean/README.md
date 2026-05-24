# Clean PR fixtures

Realistic, benign PRs that **must** pass Ward. This is the false-positive
guardrail. If something in here starts failing, either:

1. The fixture was actually adversarial all along (good, change folder); or
2. A rule got too greedy and needs tightening.

Either way, the test `test_clean_fixtures.py` keeps the project honest
about its false-positive rate.
