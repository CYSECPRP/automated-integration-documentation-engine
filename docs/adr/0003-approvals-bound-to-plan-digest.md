# ADR 0003: Approvals are bound to a digest of the plan, and changes ship as pull requests

- Status: Accepted
- Date: 2026-10-29

## Context

Automated remediation is useful only if people trust it. Approvals given in a chat or a ticket
are disconnected from what is eventually executed: new findings can appear between review and
execution, and a plan file can be edited after someone looked at it. At the same time, the
engine's token should be able to do as little as possible.

## Decision

- Only failed checks whose policy declares a remediation action are planned, and an action is
  executable only when its action type **and** its target are on the governance allowlists.
  Everything else is recorded as blocked, with the reason, for a human to handle.
- The plan digest is the SHA-256 of the canonical JSON of the run id and every planned action.
  `govflow approve` must quote that digest and is refused if it does not match, if nothing is
  executable, or if separation of duties is enabled and the approver is the requester.
- `govflow apply` is a dry run by default. `--execute` requires a matching approval and opens one
  pull request per action, adding the file and a change record. It never pushes to a default
  branch and skips files that already exist.
- In GitHub Actions the approval is the required-reviewer approval of the protected
  `remediation` environment; the workflow records that reviewer against the digest produced by
  the scan job.

## Consequences

- What was reviewed is exactly what runs; any change to the plan needs a new approval.
- Every change is reviewed twice, once as a plan and once as a pull request, where CI and branch
  protection apply as usual.
- The blast radius is bounded by the allowlists, independently of the token's permissions.
- A solo maintainer has to disable separation of duties; the protected environment remains the
  human control in that case.
