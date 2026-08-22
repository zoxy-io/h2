//! A compile-time proof must fail the build whichever way `-Dassertions` was
//! set, and this file is the fixture that proves it.
//!
//! `src/assert.zig` claims that `@inComptime()` exempts comptime assertions
//! from the option, and the claim carries real weight: `syntax.zig` checks its
//! vector kernel against a transcription of the RFC over all 256 octets in a
//! `comptime` block, and `MessageValidator` checks its pseudo-header registry
//! against its own enum. If the option silently disabled those, this package
//! would have one build configuration in which two of its correctness proofs
//! are no-ops and nothing would say so.
//!
//! A `test` block cannot check that. The first version of this gate tried, with
//! `comptime assert(true)`, which passes whether or not the comptime branch
//! exists at all — a tautology wearing a proof's name. So this is a *negative*
//! fixture instead: `build.zig` compiles it and requires the build to fail with
//! the error below. Delete the `@inComptime()` branch from `src/assert.zig`,
//! build with `-Dassertions=false`, and this file starts compiling — which is
//! the failure the gate exists to catch.

const assert = @import("h2").assertions.assert;

comptime {
    // Deliberately false. Reached through an ordinary function rather than
    // written inline, because that is the shape the real proofs have — they
    // call `rejects()` and `Pseudo.name()`, not `assert` directly — and
    // `@inComptime()` has to propagate through the call for them to be checked.
    assert(alwaysFalse());
}

fn alwaysFalse() bool {
    return 1 == 2;
}
