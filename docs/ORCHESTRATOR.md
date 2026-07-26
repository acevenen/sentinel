# Guarded orchestration

`sentinel orchestrate` produces an advisory plan for the only valid next
methodology stage. It does not execute tools. This separation keeps the model
on the judgment side of the boundary while deterministic code controls scope,
tool eligibility, authorization, audit, and human approval.

```text
captured target content
        |
        v
taxonomy + guard detectors --block--> tamper-evident audit
        |
        v
safe finding projection --> planner --> stage/tool policy --> authz scope gate
                                                        |
                                      operator review / confirmation
```

The default `--planner auto` uses the existing Anthropic client when
`ANTHROPIC_API_KEY` is present and otherwise uses the deterministic methodology
planner. `--planner claude` requires the key; `--planner methodology` is fully
offline and is the recommended reproducible CI mode.

Raw captured content and finding prose never enter the Claude prompt. Sentinel
first scans every `--content` file as untrusted tool output. Any detector
finding stops planning before the model is called. The model sees only the
engagement identifier, requested target, methodology state, and non-prose
finding metadata such as IDs, severity, CWE, and OWASP tags.

Example local dry-run:

```sh
sentinel orchestrate http://127.0.0.1:3000 \
  --engagement local-lab \
  --authorized \
  --planner methodology \
  --dry-run
```

Every model proposal is reclassified as active by trusted code, limited to a
tool registered for the next methodology stage, and sent through the same
authorization gate as a direct adapter invocation. A model cannot downgrade an
action, change the requested target, skip a stage, or authorize itself.
Intrusive proposals remain `awaiting-operator-confirmation` unless the
engagement has written authorization and the current action is explicitly
confirmed.
