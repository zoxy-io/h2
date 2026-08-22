//! h2 — HTTP/2 frame codec (RFC 9113 sections 4-6) and HPACK (RFC 7541).
//!
//! Bytes in, frames and header fields out. Nothing here reads a socket or
//! holds connection state: the two consumers do not share a runtime, so
//! anything that needs one belongs to them. See README.md for scope and
//! docs/TIGER_STYLE.md for the rules `zig build lint` enforces.

const std = @import("std");

pub const hpack = @import("hpack.zig");

test {
    _ = hpack;
}
