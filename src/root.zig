//! h2 — HTTP/2 frame codec (RFC 9113 sections 4-6), HPACK (RFC 7541), and the
//! field validity rules of RFC 9113 section 8.2.
//!
//! Bytes in, frames and header fields out. Nothing here reads a socket or
//! holds connection state: the two consumers do not share a runtime, so
//! anything that needs one belongs to them. See README.md for scope and
//! docs/TIGER_STYLE.md for the rules `zig build lint` enforces.

const std = @import("std");

pub const fields = @import("fields.zig");
pub const frame = @import("frame.zig");
pub const hpack = @import("hpack.zig");

test {
    _ = fields;
    _ = frame;
    _ = hpack;
}
