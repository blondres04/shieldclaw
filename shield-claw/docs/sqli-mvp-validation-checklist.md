# SQLi MVP Validation Checklist

Use this checklist before a demo or release-readiness decision. It is manual by
design because the MVP acceptance path depends on a live Docker Compose target,
an LLM provider, and an operator approval decision.

## Scope

- Supported MVP class: Semgrep `CWE-89` SQL injection only.
- Target fixture: `test_repos/vulnerable-flask-app`.
- Required outputs: JSON and Markdown.
- Required positive case: one approved SQLi finding reaches `TRUE_POSITIVE`.
- Required negative/no-detonation case: one rejected SQLi finding reaches
  `REJECTED` and does not generate or detonate a PoC.
- Required boundary case: non-`CWE-89` findings are visible but not scored,
  approved, PoC-generated, or detonated by default.

SARIF export may be spot-checked if desired, but it is not the SQLi MVP release
gate.

## Preconditions

- Docker Desktop or Docker Engine is running.
- Python dependencies are installed with `pip install -r shield-claw/requirements.txt -r shield-claw/requirements-dev.txt -e shield-claw/`.
- Semgrep is installed in the active environment.
- An LLM provider is available through either Ollama or OpenAI.
- The attacker image is built or `SHIELDCLAW_ATTACKER_IMAGE` points at a usable
  image.

## Prepare Semgrep Input

```bash
mkdir -p test_repos/vulnerable-flask-app/.shieldclaw/reports
```

```bash
semgrep --config=auto \
  --json \
  -o ./report-sqli-semgrep.json \
  test_repos/vulnerable-flask-app/
```

Confirm the Semgrep JSON contains at least one `CWE-89` finding.

## Approved SQLi True Positive

1. Start a fresh scan without auto-approval:

   ```bash
   python -m shieldclaw run \
     --target test_repos/vulnerable-flask-app \
     --semgrep-output ./report-sqli-semgrep.json \
     --provider ollama \
     --output-format json \
     --output test_repos/vulnerable-flask-app/.shieldclaw/reports/awaiting.json
   ```

2. Capture the `scan_id` and SQLi `finding_id` from the JSON report. The SQLi
   finding should be `AWAITING_APPROVAL`.

3. Approve the SQLi finding:

   ```bash
   python -m shieldclaw approve <scan_id> <finding_id> \
     --target test_repos/vulnerable-flask-app \
     --note "SQLi MVP approved validation case"
   ```

4. Resume and write JSON:

   ```bash
   python -m shieldclaw run \
     --target test_repos/vulnerable-flask-app \
     --semgrep-output ./report-sqli-semgrep.json \
     --resume <scan_id> \
     --provider ollama \
     --timeout 60 \
     --output-format json \
     --output test_repos/vulnerable-flask-app/.shieldclaw/reports/approved.json
   ```

5. Resume again or rerun the completed scan output as Markdown if needed:

   ```bash
   python -m shieldclaw run \
     --target test_repos/vulnerable-flask-app \
     --semgrep-output ./report-sqli-semgrep.json \
     --resume <scan_id> \
     --provider ollama \
     --timeout 60 \
     --output-format markdown \
     --output test_repos/vulnerable-flask-app/.shieldclaw/reports/approved.md
   ```

Expected result:

- SQLi finding has `outcome: TRUE_POSITIVE`.
- SQLi finding has `outcome_kind: DETONATION_VERDICT`.
- SQLi finding states that `TRUE_POSITIVE` required exit-code evidence plus
  Tier-2 corroboration.
- Evidence summary mentions `exit_code` and at least one Tier-2 observer such
  as `target_logs` or `docker_diff`.

## Rejected SQLi No-Detonation

1. Start a second fresh scan without auto-approval.
2. Reject the SQLi finding:

   ```bash
   python -m shieldclaw approve <rejected_scan_id> <finding_id> \
     --target test_repos/vulnerable-flask-app \
     --reject \
     --note "SQLi MVP rejected no-detonation case"
   ```

3. Resume the rejected scan and write JSON plus Markdown.

Expected result:

- SQLi finding has `state: REJECTED`.
- SQLi finding has `outcome: REJECTED`.
- SQLi finding has `outcome_kind: NO_DETONATION`.
- Outcome summary says no PoC was generated or detonated because the operator
  rejected approval.
- `pocs` table has no PoC for the rejected finding.
- Docker detonation logs show no attacker run for the rejected finding.

## SQLi-Only Boundary Check

Run the mixed-CWE unit fixture through the pipeline:

```bash
python -m shieldclaw run \
  --target test_repos/vulnerable-flask-app \
  --semgrep-output shield-claw/tests/fixtures/semgrep_5dv.json \
  --provider ollama \
  --output-format json \
  --output test_repos/vulnerable-flask-app/.shieldclaw/reports/mixed-boundary.json
```

Expected result:

- The two `CWE-89` findings are scored and rest in `AWAITING_APPROVAL`.
- The non-`CWE-89` findings are `DEFERRED` or otherwise reported as
  static/out-of-scope no-detonation outcomes.
- No non-`CWE-89` finding is `APPROVED`, `POC_GENERATED`, or `VERDICTED` by
  default.

## CI Companion Gate

CI runs a non-Docker SQLi MVP unit gate covering:

- default SQLi-only boundary,
- approval/rejection lifecycle,
- rejected no-detonation behavior,
- JSON and Markdown outcome wording.

The Docker checklist above remains the release/demo evidence gate.
