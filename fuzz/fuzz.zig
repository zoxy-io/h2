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

/// Operations in one dynamic-table sequence, so a failing case stays short.
const operations_max = 64;

/// Blocks per round-trip sequence, and fields per block.
const blocks_max = 8;
const fields_max = 16;

/// Room for a block against the text that went into it. A literal costs its
/// octets plus a few of framing, and Huffman only ever shortens under the
/// `.if_shorter` default, so three times the drawn text is slack rather than a
/// bound anything should reach.
const block_expansion_max = 3;

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

test "fuzz: hpack round trip" {
    try std.testing.fuzz({}, fuzzRoundTrip, .{});
}

/// Encode a drawn header list, decode it back, and require the same fields.
///
/// The property is stronger than it looks, because the two sides carry
/// independent dynamic tables that must evolve identically. A block decodes
/// correctly only if the encoder's table and the decoder's agree at every
/// insertion and eviction, so a disagreement of one entry corrupts not this
/// block but the *next* one — which is why the loop below sends several blocks
/// through one pair rather than one block through a fresh pair.
fn fuzzRoundTrip(_: void, smith: *std.testing.Smith) !void {
    var encoder_storage: hpack.Encoder.Storage(table_capacity) = .{};
    var encoder = encoder_storage.encoder(.dynamic);

    var decoder_storage: hpack.DynamicTable.Storage(table_capacity) = .{};
    var decoder = hpack.Decoder.init(decoder_storage.table(), list_size_max);

    var blocks: u32 = 0;
    while (blocks < blocks_max and !smith.eosWeightedSimple(6, 1)) {
        blocks += 1;

        var text: [input_max]u8 = undefined;
        var fields: [fields_max]hpack.Field = undefined;
        var used: usize = 0;
        var count: usize = 0;
        while (count < fields_max and !smith.eosWeightedSimple(8, 1)) {
            var drawn: [96]u8 = undefined;
            const length = smith.slice(&drawn);
            if (used + length > text.len) break;
            @memcpy(text[used..][0..length], drawn[0..length]);

            const split = if (length == 0) 0 else smith.value(u32) % (length + 1);
            fields[count] = .{
                .name = text[used..][0..split],
                .value = text[used + split ..][0..(length - split)],
                .never_indexed = smith.value(bool),
            };
            used += length;
            count += 1;
        }

        var block: [input_max * block_expansion_max]u8 = undefined;
        const encoded = encoder.encode(&block, fields[0..count]);
        // A short block is an ordinary outcome, not a failure: the encoder
        // stops rather than mutating a table for octets it did not write. What
        // it did write must decode exactly.
        std.debug.assert(encoded.fields <= count);

        var buffer: [input_max * block_expansion_max]u8 = undefined;
        var iterator = decoder.iterate(&buffer, block[0..encoded.written]);
        for (fields[0..encoded.fields]) |want| {
            const got = (try iterator.next()) orelse unreachable;
            std.debug.assert(std.mem.eql(u8, want.name, got.name));
            std.debug.assert(std.mem.eql(u8, want.value, got.value));
            std.debug.assert(want.never_indexed == got.never_indexed);
        }
        std.debug.assert((try iterator.next()) == null);

        // The invariant that keeps a connection decodable past its first block.
        std.debug.assert(encoder.table.size == decoder.table.size);
        std.debug.assert(encoder.table.count == decoder.table.count);
    }
}

test "fuzz: dynamic table" {
    try std.testing.fuzz({}, fuzzDynamicTable, .{});
}

/// The dynamic table's state machine directly, at `capacity_max` rather than
/// at a comfortable 4 KiB.
///
/// The decoder target above reaches this type only through whatever a header
/// block can express, and every other test in the package uses a small table.
/// That is how a `u16` offset overflow at exactly `capacity_max` survived a
/// review and a full test suite: the arithmetic is only wrong at the top of the
/// range, and nothing went there. The ring, the live span and the rebase all
/// interact here, so this drives them as a sequence rather than as one call.
fn fuzzDynamicTable(_: void, smith: *std.testing.Smith) !void {
    var storage: hpack.DynamicTable.Storage(hpack.DynamicTable.capacity_max) = .{};
    var table = storage.table();

    var operations: u32 = 0;
    // Bounded by the draw: `eos` ends it, and the counter caps a run the smith
    // decides not to end.
    while (operations < operations_max and !smith.eosWeightedSimple(24, 1)) {
        operations += 1;
        switch (smith.value(enum { insert, resize, read, clear })) {
            .insert => {
                var octets: [input_max]u8 = undefined;
                const length = smith.slice(&octets);
                const split = if (length == 0) 0 else smith.value(u16) % length;
                table.insert(.{ .name = octets[0..split], .value = octets[split..length] });
            },
            .resize => {
                const capacity = smith.value(u32) % (hpack.DynamicTable.capacity_max + 1);
                table.setCapacity(capacity) catch {};
            },
            .read => {
                var position: u32 = 0;
                while (position < table.count) : (position += 1) {
                    const field = table.get(position).?;
                    std.mem.doNotOptimizeAway(field.name.len);
                    std.mem.doNotOptimizeAway(field.value.len);
                }
            },
            .clear => table.clear(),
        }

        // The span invariants, which every operation above has to preserve.
        std.debug.assert(table.size <= table.capacity);
        std.debug.assert(table.begin <= table.end);
        std.debug.assert(table.end <= table.arena.len);
        if (table.count == 0) std.debug.assert(table.begin == table.end);
    }
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
