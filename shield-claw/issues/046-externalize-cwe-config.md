# Issue #46: Externalize CWE verdict map to config file

- **Tier:** 3 (Capability)
- **Blocked by:** #42 (multi-CWE conflict resolution must be in place first)
- **afk:** true

## What to build

Move the hardcoded `_CWE_VERDICTS` dictionary from `triage/classifier.py` into an external config file (YAML or TOML) so operators can extend the CWE-to-verdict mapping without modifying source code. The classifier loads the config at startup and falls back to a bundled default if no user config is found.

## Acceptance criteria

- [ ] CWE verdict mapping lives in an external config file (e.g., `cwe_verdicts.yml`)
- [ ] A bundled default config ships with the package (matching current hardcoded values)
- [ ] Operator can override by placing a custom config at a documented path
- [ ] Classifier loads and validates the config at startup (fail fast on malformed config)
- [ ] Multi-CWE conservative resolution (from #42) works with the externalized config
- [ ] Unit test: custom config with new CWE mapping → classifier returns the configured verdict
- [ ] Unit test: missing config → falls back to bundled default

## Relevant modules

- `src/shieldclaw/triage/classifier.py`
