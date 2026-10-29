# Architecture decision records

Short records of the decisions that shape `govflow`, in the format described by Michael Nygard:
context, decision and consequences.

| ADR | Decision |
| --- | --- |
| [0001](0001-policies-as-declarative-yaml.md) | Policies are declarative YAML with a small, safe condition language |
| [0002](0002-hash-chained-audit-log.md) | Evidence is a hash-chained, append-only JSONL audit log |
| [0003](0003-approvals-bound-to-plan-digest.md) | Approvals are bound to a digest of the plan, and changes ship as pull requests |
| [0004](0004-offline-fixtures-drive-real-code.md) | The demo and tests run the real connector code against recorded fixtures |
