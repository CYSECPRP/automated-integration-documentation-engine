# ADR 0001: Policies are declarative YAML with a small, safe condition language

- Status: Accepted
- Date: 2026-10-29

## Context

Policies are read by more people than the ones who write code: security engineers, auditors and
the teams who have to fix findings. A policy has to carry its rationale, remediation steps and
framework references next to the check itself, and it must be safe to load from a directory that
someone else maintains.

The options considered were:

- **Python plugins:** unlimited expressiveness, but loading a policy means running arbitrary
  code, and reviewing one means reading a program.
- **Open Policy Agent / Rego:** powerful and widely used, but adds a separate runtime and a
  language most reviewers would have to learn first.
- **JSON Schema:** declarative, but awkward for "no ingress rule may expose port 22 to
  `0.0.0.0/0`", which needs quantifiers and combined conditions on list items.
- **YAML documents with a small condition language** built for this engine.

## Decision

Policies are YAML documents validated by Pydantic models with `extra="forbid"`. The `check`
uses a small declarative language: comparisons on dotted paths (`eq`, `in`, `contains`, `gte`,
`exists`, ...), `all` / `any` / `not`, and quantifiers over lists (`any_item`, `all_items`,
`no_item`). Each check is parsed into an abstract syntax tree when the policy is loaded, so
mistakes fail fast with the file name and the offending node.

Evaluation uses three-valued logic. If a check depends on data the connector could not read, the
result is *unknown* and the finding is reported as *not assessed* together with the reason.

## Consequences

- Policies are safe to load, easy to review in a pull request and readable by non-developers.
- Missing permissions can never turn into a false *pass* or a false *fail*.
- The language is deliberately less expressive than Rego. A check that needs a new operator
  requires a code change, reviewed like any other change to the engine.
