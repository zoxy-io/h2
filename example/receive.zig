//! The receive path, end to end: octets off a connection to validated request
//! fields.
//!
//! This is the README's usage example, and it is a compiled, run program rather
//! than a snippet so that the README cannot drift from the API. `zig build ci`
//! runs it.
//!
//! It is deliberately the *server* side of a request, because that is the path
//! where every part of the package appears at once — a frame header, a payload,
//! a field block spread across CONTINUATION frames, HPACK, and the section 8
//! rules that decide whether the result is a message at all. A client's receive
//! path is the same code with `.kind = .response`.
//!
//! What is not here is the connection: no socket, no stream table, no flow
//! control, no SETTINGS exchange. Those differ per consumer and stay in the
//! consumer. See README.md.

const std = @import("std");
const h2 = @import("h2");

/// Everything a connection needs to receive field blocks, in one place so the
/// sizes are visible together.
///
/// Every buffer is caller-owned and caller-sized — the package never allocates
/// — and every size here traces to a setting or an RFC clause rather than to a
/// number that seemed large enough.
const Receiver = struct {
    /// `SETTINGS_HEADER_TABLE_SIZE` as we advertise it (RFC 7541 section 4.2).
    hpack_storage: h2.hpack.DynamicTable.Storage(4096) = .{},
    /// Where CONTINUATION fragments are joined. Its length *is* the bound on a
    /// field block, which is what stops the 2024 CONTINUATION flood: a peer
    /// that never sends END_HEADERS runs out of this instead of out of memory.
    block_buffer: [16 * 1024]u8 = undefined,
    /// Where decoded names and values are written. Separate from the block,
    /// because a Huffman-coded field expands.
    field_buffer: [8 * 1024]u8 = undefined,
};

/// `SETTINGS_MAX_FRAME_SIZE` as we advertise it: what we are willing to
/// receive, not what the peer said (RFC 9113 section 6.5.2).
const max_frame_size: u32 = h2.frame.Header.max_frame_size_min;

/// RFC 7541 section 6.5.2's header list size, the bound on what a block may
/// decode to. Distinct from the buffer above: this is the protocol's bound and
/// that one is the structural bound, and a compression bomb has to be stopped
/// by whichever is smaller.
const list_size_max: u32 = 32 * 1024;

pub fn main() !void {
    var receiver: Receiver = .{};

    // One request, framed as a HEADERS frame split by a CONTINUATION — the
    // shape a real connection produces and a hand-written test usually does
    // not. Built here because this example has no socket to read it from.
    var wire_storage: [512]u8 = undefined;
    const wire = try encodeRequest(&wire_storage);

    var assembler: h2.frame.BlockAssembler = .init(
        &receiver.block_buffer,
        h2.frame.BlockAssembler.frames_max_default,
    );
    var decoder: h2.hpack.Decoder = .init(receiver.hpack_storage.table(), list_size_max);

    var offset: usize = 0;
    while (offset < wire.len) {
        // 1. The nine-octet frame header, and everything it can decide on its
        //    own: whether the length is legal for the type, and whether the
        //    stream identifier is.
        const header = try h2.frame.Header.parse(wire[offset..]);
        try header.validate(max_frame_size);
        offset += h2.frame.Header.octets;

        // 2. The payload, sliced by the length the header declared.
        const body = wire[offset..][0..header.length];
        offset += header.length;
        const payload = try h2.frame.payload.parse(header, body);

        // 3. The CONTINUATION state machine. It answers whether this frame was
        //    allowed to arrive at all — a CONTINUATION with no block open, or
        //    any other frame interleaved into one, is a connection error.
        const accepted = try assembler.accept(header, &payload);
        const block = switch (accepted) {
            .passthrough, .fragment => continue,
            .block => |complete| complete,
        };

        // 4. HPACK, and the section 8 rules, in one pass over the fields.
        try handleRequest(&decoder, &receiver.field_buffer, block);
    }
}

/// Decode one field block and check that it is a well-formed request.
///
/// The decoder is an iterator rather than a list, and `MessageValidator` is fed
/// one field at a time for the same reason: the slices a field carries borrow
/// from `buffer`, which the next field may reuse. Nothing is copied and nothing
/// is allocated.
fn handleRequest(
    decoder: *h2.hpack.Decoder,
    buffer: []u8,
    block: h2.frame.BlockAssembler.Block,
) !void {
    var validator: h2.fields.MessageValidator = .init(.{
        .kind = .request,
        // The stricter reading of RFC 9113 section 8.2.1. A proxy forwarding
        // into HTTP/1.1 wants this one; see README.md.
        .rules = .strict,
    });

    var iterator = decoder.iterate(buffer, block.fragment);
    while (try iterator.next()) |field| {
        // Refuses the CR and LF that would split a request on an HTTP/1.1
        // upstream, the uppercase names, the connection-specific fields, and
        // everything RFC 9113 section 8.3 says about pseudo-headers.
        try validator.field(&field);
        std.debug.print("{s}: {s}\n", .{ field.name, field.value });
    }
    // Presence rules: what a request had to carry, which is only decidable
    // once the block is over.
    try validator.finish();

    std.debug.print(
        "stream {d}, end_stream={}\n",
        .{ block.stream_identifier, block.end_stream },
    );
}

/// Build the request this example reads back, so that it has octets to work on.
///
/// The send path in miniature: encode the fields with HPACK, then frame them.
/// Splitting the block across a CONTINUATION is the point — it is what makes
/// the assembler above do anything.
fn encodeRequest(target: []u8) ![]const u8 {
    var storage: h2.hpack.Encoder.Storage(4096) = .{};
    var encoder = storage.encoder(.dynamic);

    var block: [256]u8 = undefined;
    const encoded = encoder.encode(&block, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "accept-encoding", .value = "gzip, deflate" },
    });
    // `encode` cannot fail: it reports how many fields fit, so a short buffer
    // is a partial block rather than a table desynchronized from the peer's.
    if (encoded.fields != 5) return error.BufferTooSmall;

    // `Header.length` is a `u24`, because the wire field is: the length is not
    // a `usize` that happens to be small.
    const split: u24 = @intCast(encoded.written / 2);
    const rest: u24 = @intCast(encoded.written - split);
    var written: usize = 0;

    // HEADERS carrying the first half, without END_HEADERS.
    written += try renderFrame(target[written..], .{
        .length = split,
        .frame_type = .headers,
        .flags = h2.frame.Flag.end_stream.bit(),
        .stream_identifier = 1,
    }, block[0..split]);

    // CONTINUATION carrying the rest, with END_HEADERS.
    written += try renderFrame(target[written..], .{
        .length = rest,
        .frame_type = .continuation,
        .flags = h2.frame.Flag.end_headers.bit(),
        .stream_identifier = 1,
    }, block[split..encoded.written]);

    return target[0..written];
}

fn renderFrame(target: []u8, header: h2.frame.Header, body: []const u8) !usize {
    std.debug.assert(header.length == body.len);
    const header_octets = try header.render(target);
    @memcpy(target[header_octets..][0..body.len], body);
    return header_octets + body.len;
}
