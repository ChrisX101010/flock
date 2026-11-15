# Regression watchdog

This repository's bot monitors **CI health**, not live traffic. It does not
certify security, detect every vulnerability or protect a running node from
intrusion. No AI service, external model, auto-fix or auto-merge is involved.

## Execution

Existing pull-request and push checks remain in place. `Regression watchdog`
runs daily at 02:17 UTC or on manual dispatch. It calls the existing CI twice,
sequentially, with clean hosted-runner jobs and the same run commit. Each test
job has a 30-minute timeout. Goose uses its existing Linux sanitizer profile;
Flock uses its Phase 1–19 gate and existing pinned Goose compiler.

The first successful default-branch watchdog run establishes a baseline.
Failed setup, dependency installation, compilation, cancellations and unrelated
failed gates do not automatically open issues. These still appear as failed
Actions runs and need maintainer attention.

## Reporting

`Regression reports` runs separately with `actions: read`, `contents: read`
and `issues: write`. It does not check out code, download artifacts, execute
test output, inherit project secrets or access production keys. Its embedded
policy is the same code tested by `.github/watchdog-policy.test.cjs`.

It verifies the repository, default branch, workflow identity/path, event, SHA
and run metadata through GitHub's API. A recent successful matching watchdog
run (within 14 days) and the same allowlisted test step failing in both attempts
are required. A repeated gate failure can still be caused by environment or
dependency drift; it does not establish root cause or security severity.

At most one issue is opened per failed run. Open **and closed** bot issues are
deduplicated by gate and last-green baseline, so closing an issue does not
cause daily reposts. A subsequent green baseline allows a new report for a new
failure. Issues contain only gate/commit/run metadata, not raw logs, crash
inputs or a generated exploit description. Possible security defects require
private maintainer triage; do not paste sensitive inputs into public issues.

The bot runs only in this repository. It does not file issues in upstream Goose
or any third-party project. Branch rules, required checks and private reporting
settings are administered separately; this change does not enable them.

## Checks and activation

Run `node --test .github/watchdog-policy.test.cjs` locally. Tests use a mock API
and never open real issues. The scheduled workflow and workflow_run reporter
activate only after a reviewed merge into the default branch, with Actions
enabled. Feature-branch manual runs cannot publish issues. A future run can be
started manually from the Actions tab; do not insert intentional failing code
into master to test reporting.

To stop automatic issues, disable `Regression reports` in Actions. To stop
scheduled compute, disable `Regression watchdog` as well. Neither operation
requires revoking a PAT: no PAT is used. Existing ordinary CI is independent.

This first version reuses existing tests. Coverage-guided fuzz targets,
additional property/model tests, security advisory automation and live Flock
devnet monitoring are separate future work, not delivered by this workflow.
