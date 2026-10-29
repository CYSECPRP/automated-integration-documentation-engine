# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/CYSECPRP/automated-integration-documentation-engine/security/advisories/new).
Do not open a public issue for security problems.

Include the affected commit, steps to reproduce and the impact you observed. Reports are
acknowledged within five working days.

## Supported versions

Only the latest commit on `main` receives security fixes.

## Security design

- **Read-only by default.** Scans only read data. Changes require `govflow apply --execute`,
  an approval bound to the exact plan digest, and an allowlisted action and target.
- **Changes go through review.** Remediation opens pull requests; it never pushes to a
  default branch or calls admin APIs.
- **No code in policies.** Policy checks are declarative and parsed into a fixed set of
  operators. YAML is always loaded with `yaml.safe_load`.
- **Tamper-evident history.** Every run step is written to a hash-chained audit log, and runs
  are refused if the log or plan was altered.
- **Safe output.** HTML is rendered with Jinja2 autoescaping and a restrictive Content
  Security Policy; Markdown output escapes untrusted text.
- **Secrets stay secret.** Tokens are read from the environment, never written to disk, logs,
  error messages or reports, and pretty tracebacks with local variables are disabled.
- **Pinned supply chain.** GitHub Actions are pinned to full commit SHAs, dependencies are
  locked with `uv.lock`, and Dependabot proposes updates with a cooldown.
