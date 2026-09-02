# h2 style — adopted from zoxy's TigerStyle

h2 adopts [zoxy's TIGER_STYLE](https://github.com/zoxy-io/zoxy/blob/main/docs/TIGER_STYLE.md),
which in turn adopts [TigerBeetle's](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
Those are the source of truth. This file records only the **deltas** that being a
library shared by two different runtimes forces.

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

The structure that genuinely needs storage is HPACK's dynamic table, and it now
lives in zoxy-io/hpack under the same rule: the caller passes a fixed buffer
sized by the `SETTINGS_HEADER_TABLE_SIZE` it advertises, and a caller
advertising `0` passes no buffer and the decoder's table disappears. What is
left here is `BlockAssembler`'s buffer, whose length *is* the bound on a field
block.

### Put a limit on everything

Applies with more force here than anywhere in zoxy. CONTINUATION frames **are**
the unbounded-loop surface, and the compression-bomb surface is one call away in
hpack. Every bound is a protocol bound with a name — `SETTINGS_MAX_FRAME_SIZE`,
`SETTINGS_MAX_HEADER_LIST_SIZE` — so there is never an excuse for an uncounted
loop.

### Explicitly-sized integers

zoxy states this as a general hygiene rule. Here it is the wire format:
frame length is `u24`, stream identifiers and window increments are `u31`, flags
are `u8`, settings identifiers are `u16` with `u32` values. A `usize` in this
codebase is almost always a bug. The reserved bit that makes a stream id `u31`
rather than `u32` is exactly the kind of thing this rule exists to keep visible.

### index / count / size

zoxy's rule that `index`, `count` and `size` are distinct types that must be
cast explicitly still applies, though its sharpest instance went to hpack with
the tables — HPACK's static table is 1-based and its dynamic table continues
from 62 in reverse insertion order. What is left here is quieter and no less
able to bite: a frame's `length` counts payload octets, a stream identifier
counts nothing, and `BlockAssembler` carries both at once.

## What does not apply

### "Functions run to completion without suspending"

zoxy states this rule, then gives zoxy's reason: "this is why our I/O is
callback-based (see DESIGN.md §I/O)". That rationale is a property of zoxy's
event loop and does not transfer.

Here the rule is satisfied trivially — a header codec does no I/O — so it needs
no restating. What does need stating is the part that is *not* obvious: no I/O
**type** may appear in the seam either. The temptation is specific, because a
frame codec wants to be written as `readFrame(reader)`. It cannot be. The two
consumers do not share a runtime, so a reader or writer in the signature
excludes one of them. Bytes in, frames and header fields out; the encoder writes
into a caller-owned `[]u8`. `zig build lint` enforces it.

Corollary: header fields are exposed as an **iterator**, not a callback. zoxy's
"callbacks are the last parameter" rule is about its I/O seam, and a callback
here would push each consumer's control flow into the library.

### The performance priority order

zoxy: "for a proxy the slow resource is the **network**, then syscalls/memory
bandwidth." There is no network in this package. The slow resources are **CPU and
memory bandwidth**: the nine-octet header parse, and the vectorised octet scan
the field validators run over every name and value. "Batch to amortize syscall
costs" becomes "amortize per-field costs across a whole header block".

The back-of-the-envelope discipline still applies, against those resources.

## The resolved conflict: assertions in release builds

zoxy: "assertions are always on (dev **and** release); they downgrade correctness
bugs into liveness bugs." zoxy can enforce that in its own build. A library
cannot decide it for its consumers, and here the two consumers genuinely
disagree:

- **zoxy** wants them on in production. It is the security boundary, and it
  points this decoder at the open internet.
- **zrk** is a latency-measuring tool whose entire pitch is not injecting
  client-side noise into the measurement. Header decoding is already new
  hot-path cost there (h2 makes it mandatory where HTTP/1.1 was a scan for
  CRLF), and it points this decoder at servers it chose to benchmark. The
  option is forwarded to hpack, which is where that cost actually lands.

Resolution: `-Dassertions`, **defaulting to on**. zoxy inherits the default and
states nothing; zrk opts out explicitly, in a line a reviewer can see, having
made the argument for it. Neither consumer silently gets the other's policy.

Implemented in [`src/assert.zig`](../src/assert.zig), and note *why* it needed
implementing rather than being spelled `std.debug.assert`: that is
`if (!ok) unreachable`, and `unreachable` is undefined behaviour in `ReleaseFast`
and `ReleaseSmall`, so the optimizer deletes the check. Deriving assertion
policy from the optimize mode is exactly the behaviour this replaces — a
consumer choosing ReleaseFast for throughput is not thereby choosing to ship a
codec with its invariant checks removed.

`zig build lint` forbids `std.debug.assert` under `src/`. A convention that is
not mechanical drifts back the first time someone types the familiar name.

The cost is not small and is not a worry to be waved at — it is measured, both
ways, and the table is in the commit that added the option. `zig build ci` runs
with the option on and off, because a test suite that only passes with
assertions on is a suite where something depends on an assertion for its
behaviour rather than for its correctness.

## Threat model

Write every parser in this package for **zoxy's** threat model, which is the
stricter one: hostile input from the open internet, on the assumption that the
peer is trying to make this code allocate, loop, or read out of bounds. zrk's
inputs are friendlier, but a codec with two threat models is a codec with one
threat model and a bug.

## What zoxy's file does not cover, and this package needs

- **Fuzz targets are a gate, not a nicety.** The frame parser and the field
  validators each get a `std.testing.fuzz` target asserting reject-or-parse with
  no third outcome; HPACK's equivalents went to hpack with the code they cover.
  zoxy's "let a deterministic simulator be the last line of defense" has no
  simulator to point at for a pure codec; fuzzing is the equivalent.
- **RFC 9113's own examples** ship as fixtures and run in CI; RFC 7541
  Appendix C went to hpack with the code it tests.
- **The `zig build lint` unbounded-loop check** lives in zoxy's `scripts/`. It
  is ported here, or the no-unbounded-`while (true)` rule is unenforced —
  in the one package where that rule matters most.
