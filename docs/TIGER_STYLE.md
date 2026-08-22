# h2 style — adopted from zoxy's TigerStyle

h2 adopts [zoxy's TIGER_STYLE](https://github.com/zoxy-io/zoxy/blob/main/docs/TIGER_STYLE.md),
which in turn adopts [TigerBeetle's](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
Those are the source of truth. This file records only the **deltas** that being a
sans-I/O library shared by two different runtimes forces.

> Design goals, in priority order: **safety, performance, developer experience.**

Read zoxy's file first. Everything in it applies here unless listed below.

---

## What gets stricter

### No allocator, not "no allocation after `init`"

zoxy's rule is "all memory is allocated at startup; no dynamic allocation after
`init`", proven with a `FailingAllocator` in tests. A library has no startup and
no `init` to hang that rule on, so it takes the stronger form its siblings
already ship — `hparse`: "never allocates and never copies"; `ztls`: "no engine
allocations, caller-owned buffers":

**No `std.mem.Allocator` appears anywhere in the public API.** Every buffer is
caller-owned and caller-sized. This is grep-enforceable in CI, which the
`FailingAllocator` discipline is not.

The one structure that genuinely needs storage is HPACK's dynamic table, which is
connection-lifetime, per-direction state. It stays caller-owned: the caller passes
a fixed buffer sized by the `SETTINGS_HEADER_TABLE_SIZE` it advertises. A caller
advertising `0` passes no buffer and the decoder's table disappears — a lever both
consumers want, for different reasons.

### Put a limit on everything

Applies with more force here than anywhere in zoxy. HPACK **is** the
compression-bomb surface, and CONTINUATION frames **are** the unbounded-loop
surface. Every bound is a protocol bound with a name — `SETTINGS_MAX_FRAME_SIZE`,
`SETTINGS_MAX_HEADER_LIST_SIZE`, `SETTINGS_HEADER_TABLE_SIZE` — so there is never
an excuse for an uncounted loop.

### Explicitly-sized integers

zoxy states this as a general hygiene rule. Here it is the wire format:
frame length is `u24`, stream identifiers and window increments are `u31`, flags
are `u8`, settings identifiers are `u16` with `u32` values. A `usize` in this
codebase is almost always a bug. The reserved bit that makes a stream id `u31`
rather than `u32` is exactly the kind of thing this rule exists to keep visible.

### index / count / size

HPACK's static table is **1-based** (entry 1 is `:authority`), and the dynamic
table indexes continue from 62 in reverse insertion order. zoxy's rule that
`index`, `count` and `size` are distinct types that must be cast explicitly is
load-bearing here, not hygiene.

## What does not apply

### "Functions run to completion without suspending"

zoxy states this rule, then gives zoxy's reason: "this is why our I/O is
callback-based (see DESIGN.md §I/O)". That rationale is a property of zoxy's
event loop and does not transfer.

The rule is satisfied here for a stronger reason: **this library performs no I/O
at all.** No sockets, no `std.Io`, no `Io.Reader`/`Io.Writer` in the core. It
cannot have any, because its two consumers do not share a runtime — zoxy drives
libxev completion callbacks, zrk drives zio green threads through `std.Io`. Bytes
in, decoded frames and header fields out; the caller owns every transition.

That constraint is not a compromise. It is the entire reason a shared package is
possible.

Corollary: header fields are exposed as an **iterator**, not a callback. zoxy's
"callbacks are the last parameter" rule is about its I/O seam, and a callback
here would push each consumer's control flow into the library — the one thing
sans-I/O exists to prevent.

### The performance priority order

zoxy: "for a proxy the slow resource is the **network**, then syscalls/memory
bandwidth." There is no network in this package. The slow resources are **CPU and
memory bandwidth**: Huffman decode, table lookup, and the per-field scan of a
header block. "Batch to amortize syscall costs" becomes "amortize per-field costs
across a whole header block".

The back-of-the-envelope discipline still applies, against those resources.

## The one open conflict: assertions in release builds

zoxy: "assertions are always on (dev **and** release); they downgrade correctness
bugs into liveness bugs." zoxy can enforce that in its own build. A library
cannot decide it for its consumers, and here the two consumers genuinely
disagree:

- **zoxy** wants them on in production. It is the security boundary, and it
  points this decoder at the open internet.
- **zrk** is a latency-measuring tool whose entire pitch is not injecting
  client-side noise into the measurement. HPACK decode is already new hot-path
  cost there (h2 makes header decoding mandatory where HTTP/1.1 was a scan for
  CRLF), and it points this decoder at servers it chose to benchmark.

Resolution: a **build option, defaulting to on**. zoxy inherits the default and
states nothing; zrk opts out explicitly, in a line a reviewer can see, having
made the argument for it. Neither consumer silently gets the other's policy.

## Threat model

Write every parser in this package for **zoxy's** threat model, which is the
stricter one: hostile input from the open internet, on the assumption that the
peer is trying to make this code allocate, loop, or read out of bounds. zrk's
inputs are friendlier, but a codec with two threat models is a codec with one
threat model and a bug.

## What zoxy's file does not cover, and this package needs

- **Fuzz targets are a gate, not a nicety.** The HPACK decoder and the frame
  parser each get a `std.testing.fuzz` target asserting reject-or-parse with no
  third outcome. zoxy's "let a deterministic simulator be the last line of
  defense" has no simulator to point at for a pure codec; fuzzing is the
  equivalent.
- **RFC 7541 §C test vectors** ship as fixtures and run in CI.
- **The `zig build lint` unbounded-loop check** lives in zoxy's `scripts/`. It
  is ported here, or the no-unbounded-`while (true)` rule is unenforced —
  in the one package where that rule matters most.
