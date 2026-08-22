//! Interoperability conformance against http2jp/hpack-test-case.
//!
//! See README.md for what is vendored and why. In short: RFC 7541's Appendix C
//! proves agreement with the specification, and this proves agreement with the
//! implementations a real peer is running. A decoder can satisfy the first and
//! still mishandle a representation the RFC never demonstrates.
//!
//! Lives outside `src/` because it needs an allocator, a JSON parser, and 828
//! KiB of fixtures, none of which belong in a package that promises none of the
//! first and ships the third to every consumer.
//!
//! Two directions are checked for every case:
//!
//!   1. **Decode** each implementation's octets and require our fields. The
//!      cases of one story share a compression context and must be replayed in
//!      order, which is what makes this a test of eviction rather than of
//!      representations.
//!   2. **Re-encode** the same field lists with our encoder and decode them
//!      back, which is a weaker oracle than (1) but covers field lists no
//!      Appendix C example contains.

const std = @import("std");

const h2 = @import("h2");

const hpack = h2.hpack;

const Story = struct {
    implementation: []const u8,
    story: []const u8,
    json: []const u8,
};

const stories = [_]Story{
    .{ .implementation = "nghttp2", .story = "story_00", .json = @embedFile("nghttp2/story_00.json") },
    .{ .implementation = "nghttp2", .story = "story_26", .json = @embedFile("nghttp2/story_26.json") },
    .{ .implementation = "nghttp2-change-table-size", .story = "story_00", .json = @embedFile("nghttp2-change-table-size/story_00.json") },
    .{ .implementation = "nghttp2-change-table-size", .story = "story_26", .json = @embedFile("nghttp2-change-table-size/story_26.json") },
    .{ .implementation = "haskell-http2-naive", .story = "story_00", .json = @embedFile("haskell-http2-naive/story_00.json") },
    .{ .implementation = "haskell-http2-naive", .story = "story_26", .json = @embedFile("haskell-http2-naive/story_26.json") },
    .{ .implementation = "haskell-http2-static", .story = "story_00", .json = @embedFile("haskell-http2-static/story_00.json") },
    .{ .implementation = "haskell-http2-static", .story = "story_26", .json = @embedFile("haskell-http2-static/story_26.json") },
    .{ .implementation = "haskell-http2-linear-huffman", .story = "story_00", .json = @embedFile("haskell-http2-linear-huffman/story_00.json") },
    .{ .implementation = "haskell-http2-linear-huffman", .story = "story_26", .json = @embedFile("haskell-http2-linear-huffman/story_26.json") },
};

/// Longest case in the vendored selection is 466 octets; this is slack.
const wire_max = 4096;
/// Longest name is 32 octets and longest value 82, across at most 14 fields.
const output_max = 8192;
const fields_max = 64;

/// The decoder's table is deliberately the largest this package allows.
///
/// A decoder table at least as large as the encoder's always resolves the same
/// indices: positions are newest-first, so a table that evicts later holds the
/// same recent entries in the same places, plus older ones the encoder already
/// dropped and will never name. A smaller one would not, and the corpus does
/// not record what each encoder used.
const table_capacity = hpack.DynamicTable.capacity_max;

test "every vendored story decodes to the fields its encoder started from" {
    const allocator = std.testing.allocator;

    var cases_checked: u32 = 0;
    for (stories) |story| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, story.json, .{});
        defer parsed.deinit();

        var storage: hpack.DynamicTable.Storage(table_capacity) = .{};
        var decoder = hpack.Decoder.init(storage.table(), 64 * 1024);

        const cases = parsed.value.object.get("cases").?.array;
        for (cases.items, 0..) |case, index| {
            const seqno = case.object.get("seqno").?.integer;
            // The context is shared across the story, so order is part of the
            // fixture rather than an accident of the file.
            try std.testing.expectEqual(@as(i64, @intCast(index)), seqno);

            var wire: [wire_max]u8 = undefined;
            const hex = case.object.get("wire").?.string;
            const block = try std.fmt.hexToBytes(&wire, hex);

            var buffer: [output_max]u8 = undefined;
            var iterator = decoder.iterate(&buffer, block);

            const want = case.object.get("headers").?.array;
            for (want.items) |entry| {
                // Each entry is a one-key object, which is how the corpus keeps
                // duplicate names and their order.
                var pairs = entry.object.iterator();
                const pair = pairs.next().?;
                try std.testing.expectEqual(@as(?std.json.ObjectMap.Entry, null), pairs.next());

                const got = (try iterator.next()) orelse {
                    std.debug.print("{s}/{s} case {d}: ran out at {s}\n", .{
                        story.implementation, story.story, index, pair.key_ptr.*,
                    });
                    return error.TestUnexpectedResult;
                };
                std.testing.expectEqualStrings(pair.key_ptr.*, got.name) catch |err| {
                    std.debug.print("{s}/{s} case {d}: name\n", .{ story.implementation, story.story, index });
                    return err;
                };
                std.testing.expectEqualStrings(pair.value_ptr.*.string, got.value) catch |err| {
                    std.debug.print("{s}/{s} case {d}: value for {s}\n", .{
                        story.implementation, story.story, index, pair.key_ptr.*,
                    });
                    return err;
                };
            }
            try std.testing.expectEqual(@as(?hpack.Field, null), try iterator.next());
            cases_checked += 1;
        }
    }
    // The fixtures are embedded, so an empty selection would otherwise pass in
    // silence.
    try std.testing.expectEqual(@as(u32, 600), cases_checked);
}

test "every vendored field list survives our own encoder" {
    const allocator = std.testing.allocator;

    for (stories) |story| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, story.json, .{});
        defer parsed.deinit();

        var encoder_storage: hpack.Encoder.Storage(4096) = .{};
        var encoder = encoder_storage.encoder(.dynamic);
        var decoder_storage: hpack.DynamicTable.Storage(4096) = .{};
        var decoder = hpack.Decoder.init(decoder_storage.table(), 64 * 1024);

        const cases = parsed.value.object.get("cases").?.array;
        for (cases.items, 0..) |case, index| {
            var fields: [fields_max]hpack.Field = undefined;
            var count: u32 = 0;

            const want = case.object.get("headers").?.array;
            for (want.items) |entry| {
                var pairs = entry.object.iterator();
                const pair = pairs.next().?;
                // The JSON parse owns these, and it outlives the block below.
                fields[count] = .{ .name = pair.key_ptr.*, .value = pair.value_ptr.*.string };
                count += 1;
            }

            var block: [wire_max]u8 = undefined;
            const encoded = encoder.encode(&block, fields[0..count]);
            try std.testing.expectEqual(count, encoded.fields);

            var buffer: [output_max]u8 = undefined;
            var iterator = decoder.iterate(&buffer, block[0..encoded.written]);
            for (fields[0..count]) |field| {
                const got = (try iterator.next()).?;
                std.testing.expectEqualStrings(field.name, got.name) catch |err| {
                    std.debug.print("{s}/{s} case {d}: round-trip name\n", .{
                        story.implementation, story.story, index,
                    });
                    return err;
                };
                try std.testing.expectEqualStrings(field.value, got.value);
            }
            try std.testing.expectEqual(@as(?hpack.Field, null), try iterator.next());

            // The two tables track each other across the whole story, which is
            // the invariant a single block cannot show.
            try std.testing.expectEqual(encoder.table.size, decoder.table.size);
            try std.testing.expectEqual(encoder.table.count, decoder.table.count);
        }
    }
}
