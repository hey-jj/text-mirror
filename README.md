# text-mirror

Converts binary and rich files into plain text and builds a replica text-mirror tree with a manifest that records how every file was handled.

Point it at a directory tree of documents, spreadsheets, PDFs, images, audio, video, email, and HTML. It walks the tree, detects each format by content, runs the matching converter, and writes a parallel tree of text artifacts. `Q3 Budget.xlsx` becomes `Q3 Budget.xlsx.txt` at the same relative path. The append-only JSONL manifest covers every file, including the ones that failed to convert, so the mirror always has a known denominator.

The mirror feeds downstream text tooling that cannot read binary formats. The companion crate `data-classification` is one such consumer. The text artifacts carry no in-band metadata, so the tree also serves directly as a corpus.

## Design points

- Fail closed. Every source file produces either a text artifact or a manifest record explaining why not. There is no silent skip.
- Deterministic. Converter versions, model hashes, and decode options are pinned in versioned rules data. Same inputs plus same rules re-run byte-identical.
- Incremental. The manifest is the checkpoint. A killed run resumes by re-walking and skipping completed records.
- Sandboxed. Native tools and models run as subprocess adapters under timeouts, output caps, and a no-network temp jail.
- Verifiable handoff. `text-mirror bundle` packages a mirror for transfer, and `text-mirror verify` recomputes every hash on the receiving side before any consumer touches it.

Early development. The manifest schema `text-mirror/manifest@1` and the architecture are documented in `docs/DESIGN.md`.

## License

MIT OR Apache-2.0

