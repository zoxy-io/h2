//! HPACK (RFC 7541): header compression for HTTP/2.
//!
//! `Decoder` and `Encoder` are the two entry points; everything else is
//! exposed because a consumer occasionally needs a piece on its own — zrk
//! encodes one header block at startup and replays it forever, and reaches
//! `huffman` directly to size the buffer it does that in.

const std = @import("std");

pub const DynamicTable = @import("hpack/DynamicTable.zig");
pub const Field = @import("hpack/Field.zig");
pub const huffman = @import("hpack/huffman.zig");
pub const integer = @import("hpack/integer.zig");
pub const static_table = @import("hpack/static_table.zig");

/// RFC 7541 Appendix C, machine-extracted. Public so a consumer can run the
/// same conformance vectors against its own integration.
pub const rfc7541_examples = @import("hpack/rfc7541_examples.zig");

test {
    _ = DynamicTable;
    _ = Field;
    _ = huffman;
    _ = integer;
    _ = static_table;
    _ = rfc7541_examples;
}
