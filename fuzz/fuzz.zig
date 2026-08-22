//! Fuzz harness. Lives outside `src/` because it needs the platform surfaces
//! (`std.os`, page protection) that `zig build lint` forbids in the library.
//!
//! Run modes:
//! * `zig build fuzz` — replays the seed corpus once (regression mode).
//! * `zig build fuzz --fuzz` — coverage-guided fuzzing via Zig's native fuzzer.
//!
//! docs/TIGER_STYLE.md makes fuzzing a gate rather than a nicety: a pure codec
//! has no deterministic simulator to fall back on, so this is the last line of
//! defense. The targets it will carry, per zoxy-io/zoxy#173:
//!
//! 1. **HPACK decoder** — reject-or-parse with no third outcome, plus a bound
//!    on decoded size that a compression bomb cannot cross.
//! 2. **Frame parser** — same property, plus consumed-length exactness: a
//!    successful parse of N bytes re-parses identically from exactly those N,
//!    and every strict prefix returns `error.Incomplete`.
//!
//! Neither exists yet. The wiring below is deliberately present anyway — the
//! patched test runner and the `use_llvm` requirement are the fiddly part, and
//! discovering them the day the first decoder lands is worse than proving them
//! now against a placeholder.

const std = @import("std");

// Placeholder proving the harness reaches a target at all. Delete it with the
// first real one; it asserts nothing about this package.
//
// Note the shape for whoever writes those: Zig 0.16 hands the target a
// `*std.testing.Smith` rather than a `[]const u8`, so a frame or header block
// is *drawn* from the smith (`smith.slice`, `smith.value`) instead of being
// cast out of a flat buffer. Structured drawing is a better fit for both
// targets anyway — a frame header has fields, not bytes.
test "fuzz: harness wiring" {
    try std.testing.fuzz({}, fuzzWiring, .{});
}

fn fuzzWiring(_: void, smith: *std.testing.Smith) !void {
    var buffer: [64]u8 = undefined;
    const length = smith.slice(&buffer);
    std.mem.doNotOptimizeAway(length);
}
