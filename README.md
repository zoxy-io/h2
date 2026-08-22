# h2

![GitHub License](https://img.shields.io/github/license/zoxy-io/h2?color=orange)

HTTP/2 frame codec and HPACK. Powered by Zig ⚡

**Pre-alpha — nothing is implemented yet.** This repository exists so the two
pieces of HTTP/2 that are pure — no I/O, no protocol state — get written once
and used twice.

## Scope

* **RFC 9113 frame codec** — framing only, not the connection state machine.
* **RFC 7541 HPACK** — encoder, decoder, Huffman, static and dynamic tables.

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

## Style

[`docs/TIGER_STYLE.md`](docs/TIGER_STYLE.md) — zoxy's TigerStyle, plus the
deltas a shared library forces.

## Context

* zoxy-io/zoxy#173 — HTTP/2 support in the proxy (slices #272 HPACK, #273 frame codec).
* zoxy-io/zrk#21 — HTTP/2 support in the load generator.
