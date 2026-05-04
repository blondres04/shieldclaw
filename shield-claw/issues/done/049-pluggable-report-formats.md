# Issue #49: Pluggable report formats: SARIF and markdown

- **Tier:** 3 (Capability)
- **Blocked by:** #44 (observer failure warnings must be in the data model first)
- **afk:** true

## What to build

Add an `--output-format` CLI flag supporting `json` (default, current behavior), `sarif` (GitHub Code Scanning compatible), and `markdown` (human-readable summary). Refactor `reporting/builder.py` from a single JSON serializer into a format dispatcher that delegates to format-specific renderers.

End-to-end: add the CLI flag, refactor builder.py into a dispatcher, implement SARIF renderer (conforming to SARIF 2.1.0 schema for GitHub upload), implement markdown renderer (findings grouped by verdict), and ensure `observer_warnings` from #44 are included in all formats.

## Acceptance criteria

- [ ] `--output-format json` produces current JSON output (backwards compatible)
- [ ] `--output-format sarif` produces valid SARIF 2.1.0 JSON uploadable to GitHub Code Scanning
- [ ] `--output-format markdown` produces a human-readable summary grouped by verdict
- [ ] `observer_warnings` field (from #44) appears in all three formats
- [ ] Default format is `json` when flag is omitted
- [ ] Unit test: each format renders a known scan result → snapshot assertion
- [ ] Integration test: SARIF output validates against SARIF 2.1.0 JSON schema

## Relevant modules

- `src/shieldclaw/__main__.py`
- `src/shieldclaw/reporting/builder.py`
