# Interoperability corpus

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
