# ADR 0004: The demo and tests run the real connector code against recorded fixtures

- Status: Accepted
- Date: 2026-10-29

## Context

The demo has to work for anyone, without credentials or network access: reviewers, CI and the
people evaluating the project. Tests have to be fast and deterministic. Mocking at the function
level would achieve both, but it skips exactly the code that tends to break in integrations:
pagination, status-code handling, rate limits and the mapping from API responses to resources.

## Decision

GitHub responses are recorded in a JSON fixture file keyed by `"METHOD /path"` and served through
an `httpx.MockTransport` that is injected into the real `GitHubClient`. Cloud data uses the same
`govflow-snapshot/v1` format that production runs read. `govflow demo` runs the complete
pipeline on these fixtures: scan, an execution attempt that is refused without approval, an
approval, a simulated apply and the documentation.

## Consequences

- The demo, the tests and production share the same code paths, and the demo doubles as an
  end-to-end test in CI.
- Runs are deterministic: the fixtures cover an admin and a non-admin repository, compliant and
  non-compliant settings, and blocked actions.
- Fixtures can drift from the real API over time. The weekly governance run against real
  repositories is the check for that drift.
