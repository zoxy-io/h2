# h2

![GitHub License](https://img.shields.io/github/license/zoxy-io/h2?color=orange)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-x86_64-linux.yml?label=x86_64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-aarch64-linux.yml?label=aarch64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-x86_64-windows.yml?label=x86_64-windows)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-macos.yml?label=macos)

HTTP/2 frame codec, HPACK, and field validation.

## Scope

* **RFC 9113 frame codec** — framing only, not the connection state machine.
* **RFC 7541 HPACK** — encoder, decoder, Huffman, static and dynamic tables.
* **RFC 9113 §8.2 field validation** — the octet rules that make an HTTP/2
  message well-formed, and the downgrade guard against request smuggling. A
  check, never an enforcement: what to do about a malformed field is the
  consumer's decision, and the two consumers answer differently.

Out of scope, permanently: sockets, TLS, ALPN, flow control policy, stream
scheduling, and the connection state machine. Those differ per consumer and
stay in the consumer.

## Properties

* Never allocates — no `std.mem.Allocator` in the public API.
* Never copies where a slice will do.
* Caller-owned, caller-sized buffers, including HPACK's dynamic table.
* Zero dependencies beyond the Zig toolchain.

## Consumers

* [zoxy](https://github.com/zoxy-io/zoxy) — reverse proxy, drives libxev
  completion callbacks.
* [zrk](https://github.com/zoxy-io/zrk) — load generator, drives zio green
  threads through `std.Io`.

They do not share a runtime, which is why the API is bytes in, frames and
header fields out: a reader or writer in the seam would exclude one of them.
`zig build lint` enforces it.

## Gates

```sh
zig build ci      # format check, tests, fuzz corpus, interop corpus, boundary lint
zig build bench   # decode/encode microbenchmarks (ReleaseFast)
zig build fuzz    # replay the fuzz corpus; --fuzz to actually fuzz
zig build corpus  # interoperability conformance against other implementations
zig build fmt-fix # reformat in place
```

CI runs `zig build ci` natively on each target, so the tests run rather than
merely cross-compile.

## Style

[`docs/TIGER_STYLE.md`](docs/TIGER_STYLE.md) — zoxy's TigerStyle, plus the
deltas a shared library forces. [`CLAUDE.md`](CLAUDE.md) carries the same rules
as working instructions, including the review and benchmark gates.

## Context

* zoxy-io/zoxy#173 — HTTP/2 support in the proxy (slices #272 HPACK, #273 frame codec).
* zoxy-io/zrk#21 — HTTP/2 support in the load generator.
