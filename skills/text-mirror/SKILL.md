# text-mirror operator skill

Orchestrates conversion runs with the `text-mirror` CLI. The agent sequences and reports. It makes no content judgments and never edits converted text.

## Loop, per division

1. `text-mirror scan <root>`: dry-run inventory by detected format. Review it before converting. Surface unexpected formats, size outliers, and large AV counts, because media conversion dominates wall-clock time and belongs in its own pass.
2. `text-mirror run`: convert in the background. Poll `text-mirror status` for coverage. The run is safe to kill and re-run, the manifest is the checkpoint.
3. Triage failures with `text-mirror explain <path>`. Retry only transient causes such as timeouts. Report unsupported formats upward instead of working around them.
4. `text-mirror bundle`: package the division for handoff once coverage is accepted.
5. Report coverage: converted, failed, unsupported, and dedup counts against the true denominator from the manifest.

## Rules

- Never treat a failed or unsupported record as done. Every source file ends as a text artifact or an explained manifest record.
- Never hand-edit the mirror or the manifest. Fixes go through rules changes and re-runs.
- Run `text-mirror verify` on any bundle received from another machine before consuming it.
