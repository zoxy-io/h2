//! h2 — HTTP/2 frame codec (RFC 9113 sections 4-6) and the message-level rules
//! of RFC 9113 section 8.
//!
//! HPACK is RFC 7541 and lives in zoxy-io/hpack; `hpack` below re-exports it,
//! and the doc comment there says why.
//!
//! Bytes in, frames and header fields out. Nothing here reads a socket or
//! holds connection state: the two consumers do not share a runtime, so
//! anything that needs one belongs to them. See README.md for scope and
//! docs/TIGER_STYLE.md for the rules `zig build lint` enforces.

const std = @import("std");

/// `assert` and the `-Dassertions` build option. Named for the option rather
/// than for the function, so the flag reads `h2.assertions.enabled` and the
/// function does not stutter as `h2.assert.assert`.
pub const assertions = @import("assert.zig");

pub const fields = @import("fields.zig");
pub const frame = @import("frame.zig");

/// HPACK (RFC 7541), which lives in zoxy-io/hpack and is re-exported here.
///
/// Re-exported rather than merely depended on, for two reasons. HPACK is part
/// of what "speaking HTTP/2" means, so this package's scope did not change when
/// the code moved; and `h2.hpack.Decoder` is the spelling zoxy and zrk already
/// write, so churning them to say `hpack.Decoder` would buy nothing.
///
/// It is a separate package because RFC 9204 adopts two of its pieces unchanged
/// — the prefixed integer and the Huffman code — and zoxy-io/h3 builds against
/// exactly those. The alternative was a second copy of a 900-line vectorised
/// Huffman decoder in the same organisation.
pub const hpack = @import("hpack");

test {
    _ = assertions;
    _ = fields;
    _ = frame;
    _ = hpack;
}
