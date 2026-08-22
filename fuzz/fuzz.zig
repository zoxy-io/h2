//! Fuzz targets. Lives outside `src/` because it needs platform surfaces that
//! `zig build lint` forbids in the library.
//!
//! Run modes:
//! * `zig build fuzz` — replays the seed corpus once (regression mode).
//! * `zig build fuzz --fuzz` — coverage-guided fuzzing via Zig's native fuzzer.
//!
//! docs/TIGER_STYLE.md makes fuzzing a gate rather than a nicety: a pure codec
//! has no deterministic simulator to fall back on, so this is the last line of
//! defense.
//!
//! The property every target shares is **reject or parse, with no third
//! outcome**. A decoder may return a well-formed answer or an error; what it
//! may not do is panic, read out of bounds, fail to terminate, or return an
//! answer that is quietly short. Assertions are on in the Debug build this runs
//! under, so every internal invariant joins the oracle — a decoder that reaches
//! an impossible state fails here rather than inside a proxy.
//!
//! Zig 0.16 hands a target a `*std.testing.Smith` rather than a byte slice, so
//! inputs are *drawn* — `smith.slice`, `smith.value` — instead of being cast
//! out of a flat buffer. That suits a header block: drawing a length and then
//! that many octets reaches valid-header/invalid-payload combinations a byte
//! fuzzer needs luck for.

const std = @import("std");

const h2 = @import("h2");

const hpack = h2.hpack;

/// Inputs are capped so a failing case stays small enough to read.
const input_max = 1024;

/// The decoder configuration every header-block target runs under. The output
/// buffer is deliberately far smaller than the list bound, so a compression
/// bomb has to be stopped by the structural bound rather than by the protocol
/// one.
const table_capacity = 4096;
const output_max = 2048;
const list_size_max = 64 * 1024;

/// A Huffman decoding cannot exceed 8/5 of its input: the shortest code is five
/// bits. Four times the input is room to spare, so an `OutputTooLong` from
/// these targets would be a bug in the bound rather than a small buffer.
const huffman_expansion_max = 4;

test "fuzz: hpack decoder" {
    try std.testing.fuzz({}, fuzzDecoder, .{});
}

/// Decode an arbitrary header block and check what comes back.
///
/// The bound this is really aimed at is the one CVE-2016-6581 and
/// CVE-2026-49975 both turned on: a small block must not expand without limit.
fn fuzzDecoder(_: void, smith: *std.testing.Smith) !void {
    var block: [input_max]u8 = undefined;
    const length = smith.slice(&block);

    var storage: hpack.DynamicTable.Storage(table_capacity) = .{};
    var decoder = hpack.Decoder.init(storage.table(), list_size_max);

    var buffer: [output_max]u8 = undefined;
    var iterator = decoder.iterate(&buffer, block[0..length]);

    var produced: u32 = 0;
    // Bounded: no representation is shorter than one octet of wire, so a block
    // of `length` octets cannot yield more than `length` fields.
    while (produced <= length) : (produced += 1) {
        std.debug.assert(produced <= length);
        const field = iterator.next() catch break;
        if (field == null) break;

        // A yielded field is fully formed, and the running total the decoder
        // charged itself is consistent with it.
        std.mem.doNotOptimizeAway(field.?.name.len);
        std.mem.doNotOptimizeAway(field.?.value.len);
        std.debug.assert(iterator.headerListSize() >= field.?.size());
        std.debug.assert(iterator.headerListSize() <= list_size_max);
    }
    // Whatever the input asked for, the table stayed inside the arena it was
    // given.
    std.debug.assert(decoder.table.size <= decoder.table.capacity);
}

test "fuzz: huffman decoder" {
    try std.testing.fuzz({}, fuzzHuffman, .{});
}

/// The Huffman kernel alone, where a failure localizes.
///
/// Beyond reject-or-parse: anything this decoder accepts must re-encode to the
/// bytes it came from. HPACK's Huffman coding is canonical, so a string has
/// exactly one valid encoding, and an accepted input that re-encodes
/// differently means the decoder walked a path no encoder would produce —
/// which is a second spelling of a header value, and therefore a smuggling
/// primitive rather than a cosmetic disagreement.
fn fuzzHuffman(_: void, smith: *std.testing.Smith) !void {
    var wire: [input_max]u8 = undefined;
    const length = smith.slice(&wire);

    var decoded: [input_max * huffman_expansion_max]u8 = undefined;
    const written = hpack.huffman.decode(&decoded, wire[0..length]) catch return;

    var reencoded: [input_max * huffman_expansion_max]u8 = undefined;
    const encoded_length = try hpack.huffman.encode(&reencoded, decoded[0..written]);
    std.debug.assert(encoded_length == length);
    std.debug.assert(std.mem.eql(u8, reencoded[0..encoded_length], wire[0..length]));
}

test "fuzz: huffman round trip" {
    try std.testing.fuzz({}, fuzzHuffmanRoundTrip, .{});
}

/// The other direction: every byte string encodes, and decodes back to itself.
fn fuzzHuffmanRoundTrip(_: void, smith: *std.testing.Smith) !void {
    var text: [input_max]u8 = undefined;
    const length = smith.slice(&text);

    var wire: [input_max * huffman_expansion_max]u8 = undefined;
    const encoded_length = try hpack.huffman.encode(&wire, text[0..length]);
    std.debug.assert(encoded_length == hpack.huffman.encodedLength(text[0..length]));

    var decoded: [input_max]u8 = undefined;
    const written = try hpack.huffman.decode(&decoded, wire[0..encoded_length]);
    std.debug.assert(std.mem.eql(u8, decoded[0..written], text[0..length]));
}

test "fuzz: integer codec" {
    try std.testing.fuzz({}, fuzzInteger, .{});
}

/// The prefix-integer primitive, whose worst failure is not returning at all.
fn fuzzInteger(_: void, smith: *std.testing.Smith) !void {
    var source: [64]u8 = undefined;
    const length = smith.slice(&source);
    if (length == 0) return;

    const prefix_bits: u4 = @intCast(1 + @as(u4, smith.value(u3)));
    const decoded = hpack.integer.decode(source[0..length], prefix_bits) catch return;
    std.debug.assert(decoded.octets >= 1);
    std.debug.assert(decoded.octets <= length);

    // Re-encoding must reproduce the *value*, not the octets. RFC 7541 section
    // 5.1 permits a non-minimal encoding — `{0x1f, 0x80, 0x00}` and
    // `{0x1f, 0x00}` are both 31 behind a 5-bit prefix — so asserting byte
    // identity here would fail on input the decoder accepts by design, and a
    // coverage-guided run reaches such input almost immediately. See the note
    // in Decoder.zig on why accepting both spellings is interoperation rather
    // than laxity.
    var target: [16]u8 = undefined;
    const prefix_mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    const tag: u8 = source[0] & ~prefix_mask;
    const written = try hpack.integer.encode(&target, decoded.value, prefix_bits, tag);
    std.debug.assert(written == hpack.integer.encodedLength(decoded.value, prefix_bits));
    std.debug.assert(written <= decoded.octets);

    const again = try hpack.integer.decode(target[0..written], prefix_bits);
    std.debug.assert(again.value == decoded.value);
    std.debug.assert(again.octets == written);
}
