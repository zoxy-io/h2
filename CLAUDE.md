# h2

HTTP/2 frame codec (RFC 9113 §4-§6) and HPACK (RFC 7541) in Zig 0.16. A
library, not a program: it is consumed by
[zoxy](https://github.com/zoxy-io/zoxy) (reverse proxy, libxev completion
callbacks) and [zrk](https://github.com/zoxy-io/zrk) (load generator, zio green
threads through `std.Io`). Read before writing code:

- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — enforced coding rules. It is
  zoxy's TigerStyle plus the deltas a shared library forces; the deltas are the
  part to read first, because two of them invert what the parent document says.
- [README.md](README.md) — scope, and what is permanently out of it.

Planned work is tracked as GitHub issues, not here. The design context lives in
zoxy-io/zoxy#173 and zoxy-io/zrk#21.

## Gates — run before every commit

- `zig build ci` — the format check, unit tests, the lint's own tests, the fuzz
  corpus, and the boundary lint. This is exactly what CI runs, on each target
  natively.
- `zig build bench` — the performance gate. **Not optional for a change that
  touches a decode or encode path.** Compare bands across runs, never single
  numbers: a 3% move between two runs on a laptop is noise, and reporting it as
  a regression trains everyone to ignore the gate. Say which numbers moved and
  by how much in the commit message when they move at all.
- The format gate is part of `zig build ci`, and `zig build fmt-fix` rewrites.
  The list of formatted paths lives in build.zig and nowhere else, so CI cannot
  check a different set than you do. A PostToolUse hook auto-formats files as
  they are edited, so the gate should never fail; if it does, something wrote a
  file outside the tools.

## Review — required before every commit

Run the `tiger-style-reviewer` agent on the diff before committing a slice. The
automated gates cover formatting, the boundaries, and behavior; the agent
covers the rules in docs/TIGER_STYLE.md that only a reader can check —
assertion density, function length, bounded loops, explicitly-sized integers,
naming, and whether a new limit is a named constant.

This is not a formality here. The two consumers point this code at different
threat models, and the stricter one — zoxy's, which is the open internet —
is not represented by any test that runs on a laptop.

## Policies

- **No dependencies.** `build.zig.zon` has an empty `dependencies` table and
  keeps it. `@cImport` is lint-forbidden. The one place C is admissible is
  `bench/`, for a comparison against an established implementation, which is
  outside `src/` and outside the lint's walk — the same arrangement hparse uses
  for picohttpparser.
- **No allocator, anywhere.** Not "no allocation after init" — there is no
  `init` in a library. `std.mem.Allocator` does not appear in `src/`, and
  `zig build lint` enforces it. Every buffer is caller-owned and caller-sized,
  HPACK's dynamic table included. Tests use `std.testing.allocator`.
- **No I/O types in the seam.** No `std.Io`, `std.posix`, `std.os`, `std.net`,
  `std.fs` under `src/`, lint-enforced. The temptation is specific and worth
  naming: a frame codec wants to be `readFrame(reader)`. It cannot be, because
  the two consumers do not share a runtime, and a reader in the signature
  excludes one of them. Bytes in, frames and header fields out; the encoder
  writes into a caller-owned `[]u8`.
- **Every bound is a named constant** with a comptime assert relating it to its
  neighbours. HPACK is the compression-bomb surface and CONTINUATION frames are
  the unbounded-loop surface, so "put a limit on everything" is not a style
  preference here — every limit traces to a SETTINGS parameter or an RFC
  clause, and the constant says which.
- **Every parsing change ships with its fuzz coverage.** `fuzz/` holds the
  targets; a decode path without one is not done. Note that Zig 0.16 hands the
  target a `*std.testing.Smith`, so inputs are *drawn* rather than cast out of
  a flat buffer.
- **Write to zoxy's threat model**, which is the stricter one. zrk points this
  decoder at servers it chose to benchmark; zoxy points it at the internet. A
  codec with two threat models is a codec with one threat model and a bug.
- **Workflow:** small slices, one commit per slice, descriptive commit
  messages. Push and open PRs only when asked.
