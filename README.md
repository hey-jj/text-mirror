# text-mirror

Converts binary and rich files into plain text and builds a replica text-mirror tree with a manifest that records how every file was handled.

Point it at a directory tree. It walks the tree, detects each format by content, runs the matching converter, and writes a parallel tree of text artifacts. `Q3 Budget.xlsx` becomes `Q3 Budget.xlsx.txt` at the same relative path under its division's mirror root. Shipped converters cover plain text, Markdown, CSV, and text-native developer formats, Word documents and presentations in both current and legacy formats, workbooks with hidden sheets, rows, and columns marked, text-layer PDF, HTML, and email with attachments expanded as child records. Zip archives expand into their members, each routed back through detection. Parquet, avro, and sqlite convert behind the opt-in `records-worker` feature described below. Raster images convert behind the opt-in `image-ocr` and `image-metadata` features described below. Audio and video are detected and recorded as `unsupported` with reason `engine-unpinned` until transcription engines are pinned in the rules data. The append-only JSONL manifest covers every file, including the ones that did not convert, so the mirror always has a known denominator.

The mirror feeds downstream text tooling that cannot read binary formats. The companion crate `data-classification` is one such consumer. The text artifacts carry no in-band metadata, so the tree also serves directly as a corpus.

## Design points

- Fail closed. Every source file produces either a text artifact or a manifest record explaining why not. There is no silent skip.
- Deterministic. Converter versions, model hashes, and decode options are pinned in versioned rules data. Same inputs plus same rules re-run byte-identical.
- Incremental. The manifest is the checkpoint. A killed run resumes by re-walking and skipping completed records.
- Sandboxed. Native tools and models run as subprocess adapters under timeouts, output caps, and a no-network temp jail.
- Verifiable handoff. `text-mirror bundle` packages a mirror for transfer, and `text-mirror verify` recomputes every hash on the receiving side before any consumer touches it.

Early development. The manifest schema `text-mirror/manifest@1` and the architecture are documented in `docs/DESIGN.md`.

## The records-worker feature

Parquet, avro, and sqlite conversion is an opt-in feature, `records-worker`, off by default. These parsers pull large native trees with CVE history, so they run only inside the subprocess jail, and the default build links none of them.

Build with the feature to convert these formats:

```
cargo build --release --features records-worker
```

A default build records a parquet, avro, or sqlite source as `unsupported` with reason `records-worker-not-built` and handles every other format exactly as a featured build does.

## The image features

Pixel OCR for png, jpeg, and webp is gated behind the `image-ocr` feature. The reader that lifts exif, png text-chunk, xmp, and iptc strings out of an image and records them as a hidden derived child at `<source>.d/#image-metadata` is gated behind `image-metadata`. Both are off by default and both run inside the subprocess jail.

```
cargo build --release --features image-ocr,image-metadata
```

A default build records a png, jpeg, or webp source as `unsupported` with reason `image-ocr-not-built` and writes the warning `image-metadata-not-built` on each image record, so a later build that carries the converters re-runs those files.

| Format | Handling in this release |
|---|---|
| png, jpeg, webp | In-jail pixel OCR through the `image-pixel-ocr` converter. The deployment supplies the engine. A build with `image-ocr` on decodes the raster and fails closed with `image-ocr-runtime-missing` until the engine is configured. |
| heic | Fails closed with reason `no-jailed-rasterizer`. Decoding needs an external rasterizer, and the external-rasterizer provider is not built in this release. |
| svg | The raw markup passes through as the text artifact. No pixel OCR runs. |
| ai | The PDF text layer is extracted through `pdf-subprocess`. A legacy PostScript-backed file has no PDF text layer and fails closed with a pdf-family reason. |
| tiff | Recorded as `unsupported` with reason `engine-unpinned` until a rules bump pins a decoder. |

## License

MIT OR Apache-2.0

