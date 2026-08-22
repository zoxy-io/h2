//! h2 — HTTP/2 frame codec (RFC 9113 §4-§6) and HPACK (RFC 7541).
//!
//! Nothing is implemented yet. The two namespaces below are the whole public
//! surface this package will ever have; anything that needs a socket, a
//! connection, or a stream belongs to the consumer, not here.
//!
//! See README.md for scope and docs/TIGER_STYLE.md for the rules `zig build
//! lint` enforces.

// pub const frame = @import("frame.zig");
// pub const hpack = @import("hpack.zig");

test {
    // Empty for now. Once the namespaces above land, this pulls their tests
    // into the `test` step rather than leaving them to be imported by hand —
    // a test file nobody references is a test file nobody runs.
    @import("std").testing.refAllDecls(@This());
}
