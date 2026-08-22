# Vendored corpora

Two unrelated corpora, both MIT licensed and both vendored byte-identical to
upstream so a diff against the named commit is the whole audit.

- [`hpack/`](#hpack-interoperability) — HPACK encodings from other
  implementations, for #1.
- [`frames/`](#http2-frame-fixtures) — HTTP/2 frame fixtures, for #2.

They share one test binary (`zig build corpus`) because both need an allocator
and a JSON parser, and neither belongs in a package that promises no allocator
and ships no fixtures.

# HPACK interoperability

Vendored from [http2jp/hpack-test-case](https://github.com/http2jp/hpack-test-case)
at commit `8a1406e7d14bfcb6c046021f13cc15cfb162726d` (2019-06-01), MIT licensed.
The JSON is byte-identical to upstream, so a diff against that commit is the
whole audit.

## Why this exists beside Appendix C

RFC 7541's Appendix C proves agreement with the *specification*: twelve worked
examples, all produced by one encoder. This corpus proves agreement with the
*implementations* — the same header data encoded by nghttp2, Go, Haskell, node,
Python and swift-nio, each making its own representation choices.

Those are different questions. A decoder can satisfy the RFC's examples and
still mis-handle a representation the RFC never demonstrates but a real peer
emits. Both consumers of this package point at real peers, so both questions
have to be answered.

## What is here, and why these files

Upstream is 8.2 MiB across fourteen encoders and thirty-two stories, which is
more than a test fixture should weigh. The selection covers the strategy matrix
rather than sampling it evenly — each encoder here turns a different part of
HPACK on:

The counts below are what the vendored octets actually contain, parsed
independently rather than taken from the directory names:

| directory | indexed | incremental | without | size update | Huffman / raw strings |
|---|---|---|---|---|---|
| `haskell-http2-naive` | — | — | 1334 | — | 0 / 2668 |
| `haskell-http2-static` | 125 | — | 1209 | — | 0 / 1526 |
| `haskell-http2-linear-huffman` | 787 | 430 | 117 | — | 663 / 3 |
| `nghttp2` | 787 | 430 | 117 | — | 542 / 39 |
| `nghttp2-change-table-size` | 729 | 488 | 117 | 4 | 615 / 43 |

`haskell-http2-naive` is the useful extreme: 1334 literals and not one indexed
reference, so it exercises the literal path against traffic that every other
encoder here compresses away. `nghttp2-change-table-size` is the only source
that emits a dynamic table size update, which is why it is here even though its
encoder is otherwise identical to `nghttp2`'s.

**Not covered:** the never-indexed representation (RFC 7541 section 6.2.3) does
not appear anywhere in this corpus. It is covered by unit tests in
`src/hpack/Decoder.zig` and `src/hpack/Encoder.zig`, and by Appendix C.2.3 —
but not by any encoding a real implementation produced, so nothing here proves
we agree with one about it.

Two stories each: `story_00` is three cases and small enough to read when
something fails, `story_26` is 117 cases of real browsing traffic that churns
the dynamic table through many evictions. 600 cases in total.

## Running it

`zig build corpus`, and it is part of `zig build ci`.

# HTTP/2 frame fixtures

Vendored from [http2jp/http2-frame-test-case](https://github.com/http2jp/http2-frame-test-case),
MIT licensed (`frames/LICENSE`). All 34 fixtures, because the whole corpus is
140 KiB — there is nothing to select.

Each fixture is one frame: a hex `wire`, and either a decoded `frame` or a
`null` frame with a list of RFC 9113 section 7 error codes the decode must
produce.

## What it covers

Twelve valid frames, one for every frame type RFC 9113 defines:

| type | fixture | notes |
|---|---|---|
| DATA | `data/normal` | padded |
| HEADERS | `headers/normal`, `headers/priority` | the second carries the priority fields and padding |
| PRIORITY | `priority/normal` | |
| RST_STREAM | `rst_stream/normal` | |
| SETTINGS | `settings/normal` | two parameters |
| PUSH_PROMISE | `push_promise/normal` | padded |
| PING | `ping/normal` | |
| GOAWAY | `goaway/normal` | with debug data |
| WINDOW_UPDATE | `window_update/normal` | |
| CONTINUATION | `continuation/normal`, `continuation/header` | |

And twenty-two error cases, which are the more valuable half. They map onto the
rules #2 lists almost one for one:

| rule | fixtures |
|---|---|
| padding at least the declared length | `data-frame-padding`, `headers-frame-padding`, `push_promise-frame-padding` |
| frame size fixed per type | `priority-`, `rst_stream-`, `ping-`, `window_update-`, `goaway-`, `data-frame-size` |
| SETTINGS a multiple of six, and empty when ACK | `settings-frame-size`, `settings-frame-ack-size` |
| stream identifier valid for the type | one per type: `data-`, `headers-`, `priority-`, `rst_stream-`, `settings-`, `push_promise-`, `ping-`, `goaway-frame-stream` |
| WINDOW_UPDATE increment non-zero | `window_update-frame-increment` |
| promised stream identifier even and non-zero | `push_promise-frame-promised_stream-odd`, `-zero` |

Every case names `PROTOCOL_ERROR` or `FRAME_SIZE_ERROR`, and
`push_promise-frame-padding` accepts either — which is itself worth knowing,
because it means the codec is not obliged to pick one and a test that demands a
single code would be wrong.

**Not covered:** unknown frame types, which RFC 9113 section 4.1 requires be
ignored rather than rejected; frames exceeding `SETTINGS_MAX_FRAME_SIZE`, since
a fixture cannot know what was negotiated; and the CONTINUATION flood, which is
a property of a sequence rather than of one frame. Those need tests this package
writes itself; the first two now have them in `src/frame/Header.zig`, and the
third waits on a connection layer.

Nor does any fixture record a failure's **severity** — whether it ends the
connection or only the stream. RFC 9113 makes a wrong-length PRIORITY frame a
stream error and a wrong-length RST_STREAM a connection error, and the corpus
names codes, not severities. `Header.severity` is covered by unit tests only.

## Status

`corpus/frames.zig` checks every fixture three ways: the codec's `Header.parse`
against the fixture's declared metadata, the codec against an independent
reading of the nine octets that was written before it and does not import it,
and `Header.validate` against the fixture's expected error codes.

**Seventeen of the twenty-two error cases are caught by the header alone**, and
the split is pinned in the test so it can only move deliberately. The five that
remain each need an octet of payload, and arrive with the payload codec:

| fixture | needs |
|---|---|
| `data-frame-padding`, `headers-frame-padding` | the pad length, checked against what is left |
| `push_promise-frame-promised_stream-odd`, `-zero` | the promised stream identifier's parity |
| `window_update-frame-increment` | the increment, which must not be zero |

`push_promise-frame-padding` is caught by the header, because a PADDED
PUSH_PROMISE shorter than five octets cannot hold both its pad length and its
promised stream identifier. It is also the fixture that accepts *two* error
codes, and the codec returns `FRAME_SIZE_ERROR` where a reader might expect
`PROTOCOL_ERROR` — which is why the test checks membership rather than
equality. A test written the obvious way would fail on it and be wrong.

Payload comparison is still absent: the fixtures carry decoded payloads
(`frame_payload`) that nothing yet reads.
