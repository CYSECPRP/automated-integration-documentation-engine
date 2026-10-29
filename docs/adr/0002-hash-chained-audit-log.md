# ADR 0002: Evidence is a hash-chained, append-only JSONL audit log

- Status: Accepted
- Date: 2026-10-29

## Context

Compliance evidence has to answer two questions: what happened, in which order, and has anyone
changed the record since? The engine runs on laptops and in short-lived CI jobs, so evidence
cannot depend on a database or a hosted service.

The options considered were:

- **Plain log files:** easy to write, but nothing shows whether they were edited.
- **A database with audit tables:** needs infrastructure the engine otherwise does not need.
- **A signed transparency log (for example Sigstore):** strong guarantees, but a large
  dependency for a first version.
- **A hash-chained JSONL file** stored next to the run.

## Decision

Every step appends one JSON line to `audit.jsonl` with a sequence number, timestamp, run id,
actor, event name, event data and the previous event's hash. Each event's `hash` is the SHA-256
of its canonical JSON (sorted keys, no whitespace) without the `hash` field itself. The first
event of a chain points to a genesis value of 64 zeros, or to the head of the previous run when
`--chain-from` is used.

`govflow audit verify` recomputes every hash and link and reports the first broken event.
In CI, each run is chained to the previous one, and the trail is committed to an orphan
`evidence` branch, so git history becomes a second, independent record.

## Consequences

- Edited, deleted, inserted or reordered events are detected with nothing but the file and
  standard SHA-256.
- The log stays human-readable and diff-friendly.
- Integrity is relative to a trusted head. Someone who can rewrite the whole `evidence` branch
  could recompute a consistent chain; publishing the head in the report and in workflow artifacts
  makes that visible, and signing the head is the planned next step.
