//! Conformance for http2jp/http2-frame-test-case.
//!
//! See corpus/README.md for what is vendored and why. Every fixture is checked
//! three ways, which is more than it sounds:
//!
//!   1. `frame.Header.parse` against the fixture's declared metadata.
//!   2. `frame.Header.parse` against `readHeader` below, an independent reading
//!      of the nine octets that predates the codec and does not import it.
//!   3. `frame.Header.validate` against the fixture's expected error codes.
//!
//! The second is not redundant. It is the same differential shape the two
//! Huffman kernels use: the fixtures were vendored before the codec was
//! written, and this reader was written against the RFC alongside them, so the
//! codec is measured against an expectation that existed first rather than one
//! that grew up agreeing with it.
//!
//! The header is RFC 9113 section 4.1:
//!
//!     +-----------------------------------------------+
//!     |                 Length (24)                   |
//!     +---------------+---------------+---------------+
//!     |   Type (8)    |   Flags (8)   |
//!     +-+-------------+---------------+-------------------------------+
//!     |R|                 Stream Identifier (31)                      |
//!     +=+=============================================================+

const std = @import("std");

const Fixture = struct {
    category: []const u8,
    name: []const u8,
    json: []const u8,
};

const fixtures = [_]Fixture{
    .{ .category = "continuation", .name = "header", .json = @embedFile("frames/continuation/header.json") },
    .{ .category = "continuation", .name = "normal", .json = @embedFile("frames/continuation/normal.json") },
    .{ .category = "data", .name = "normal", .json = @embedFile("frames/data/normal.json") },
    .{ .category = "error", .name = "data-frame-padding", .json = @embedFile("frames/error/data-frame-padding.json") },
    .{ .category = "error", .name = "data-frame-size", .json = @embedFile("frames/error/data-frame-size.json") },
    .{ .category = "error", .name = "data-frame-stream", .json = @embedFile("frames/error/data-frame-stream.json") },
    .{ .category = "error", .name = "goaway-frame-size", .json = @embedFile("frames/error/goaway-frame-size.json") },
    .{ .category = "error", .name = "goaway-frame-stream", .json = @embedFile("frames/error/goaway-frame-stream.json") },
    .{ .category = "error", .name = "headers-frame-padding", .json = @embedFile("frames/error/headers-frame-padding.json") },
    .{ .category = "error", .name = "headers-frame-stream", .json = @embedFile("frames/error/headers-frame-stream.json") },
    .{ .category = "error", .name = "ping-frame-size", .json = @embedFile("frames/error/ping-frame-size.json") },
    .{ .category = "error", .name = "ping-frame-stream", .json = @embedFile("frames/error/ping-frame-stream.json") },
    .{ .category = "error", .name = "priority-frame-size", .json = @embedFile("frames/error/priority-frame-size.json") },
    .{ .category = "error", .name = "priority-frame-stream", .json = @embedFile("frames/error/priority-frame-stream.json") },
    .{ .category = "error", .name = "push_promise-frame-padding", .json = @embedFile("frames/error/push_promise-frame-padding.json") },
    .{ .category = "error", .name = "push_promise-frame-promised_stream-odd", .json = @embedFile("frames/error/push_promise-frame-promised_stream-odd.json") },
    .{ .category = "error", .name = "push_promise-frame-promised_stream-zero", .json = @embedFile("frames/error/push_promise-frame-promised_stream-zero.json") },
    .{ .category = "error", .name = "push_promise-frame-stream", .json = @embedFile("frames/error/push_promise-frame-stream.json") },
    .{ .category = "error", .name = "rst_stream-frame-size", .json = @embedFile("frames/error/rst_stream-frame-size.json") },
    .{ .category = "error", .name = "rst_stream-frame-stream", .json = @embedFile("frames/error/rst_stream-frame-stream.json") },
    .{ .category = "error", .name = "settings-frame-ack-size", .json = @embedFile("frames/error/settings-frame-ack-size.json") },
    .{ .category = "error", .name = "settings-frame-size", .json = @embedFile("frames/error/settings-frame-size.json") },
    .{ .category = "error", .name = "settings-frame-stream", .json = @embedFile("frames/error/settings-frame-stream.json") },
    .{ .category = "error", .name = "window_update-frame-increment", .json = @embedFile("frames/error/window_update-frame-increment.json") },
    .{ .category = "error", .name = "window_update-frame-size", .json = @embedFile("frames/error/window_update-frame-size.json") },
    .{ .category = "goaway", .name = "normal", .json = @embedFile("frames/goaway/normal.json") },
    .{ .category = "headers", .name = "normal", .json = @embedFile("frames/headers/normal.json") },
    .{ .category = "headers", .name = "priority", .json = @embedFile("frames/headers/priority.json") },
    .{ .category = "ping", .name = "normal", .json = @embedFile("frames/ping/normal.json") },
    .{ .category = "priority", .name = "normal", .json = @embedFile("frames/priority/normal.json") },
    .{ .category = "push_promise", .name = "normal", .json = @embedFile("frames/push_promise/normal.json") },
    .{ .category = "rst_stream", .name = "normal", .json = @embedFile("frames/rst_stream/normal.json") },
    .{ .category = "settings", .name = "normal", .json = @embedFile("frames/settings/normal.json") },
    .{ .category = "window_update", .name = "normal", .json = @embedFile("frames/window_update/normal.json") },
};

/// The nine octets every frame begins with.
const header_octets = 9;

/// What those nine octets say, read here rather than borrowed from `src/`.
///
/// Deliberately independent of `frame.Header`, and deliberately written before
/// it. If the two disagree, one of them is wrong and the test says which
/// fixture found it.
const Header = struct {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_identifier: u32,
};

fn readHeader(wire: []const u8) Header {
    std.debug.assert(wire.len >= header_octets);
    return .{
        .length = (@as(u32, wire[0]) << 16) | (@as(u32, wire[1]) << 8) | wire[2],
        .frame_type = wire[3],
        .flags = wire[4],
        // The high bit is reserved and ignored on receipt (section 4.1), which
        // is a decision to encode rather than a bit to drop and forget.
        .stream_identifier = (@as(u32, wire[5] & 0x7f) << 24) | (@as(u32, wire[6]) << 16) |
            (@as(u32, wire[7]) << 8) | wire[8],
    };
}

const wire_max = 4096;

const h2 = @import("h2");
const frame = h2.frame;

/// `SETTINGS_MAX_FRAME_SIZE` for the conformance run.
///
/// The corpus predates any negotiation, so the value in force is the one RFC
/// 9113 section 6.5.2 mandates before a SETTINGS frame is exchanged. Every
/// fixture is far below it, which is why no fixture exercises the bound — see
/// corpus/README.md.
const max_frame_size = frame.Header.max_frame_size_min;

test "every fixture's declared frame agrees with its own octets" {
    const allocator = std.testing.allocator;

    var valid: u32 = 0;
    var failing: u32 = 0;
    for (fixtures) |fixture| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture.json, .{});
        defer parsed.deinit();

        var buffer: [wire_max]u8 = undefined;
        const hex = parsed.value.object.get("wire").?.string;
        const wire = try std.fmt.hexToBytes(&buffer, hex);
        try std.testing.expect(wire.len >= header_octets);
        const header = readHeader(wire);

        // The codec and the independent reader must agree on every fixture,
        // valid or not.
        const decoded = try frame.Header.parse(wire);
        std.testing.expectEqual(header.length, @as(u32, decoded.length)) catch |err| {
            std.debug.print("{s}/{s}: codec length\n", .{ fixture.category, fixture.name });
            return err;
        };
        try std.testing.expectEqual(header.frame_type, @intFromEnum(decoded.frame_type));
        try std.testing.expectEqual(header.flags, decoded.flags);
        std.testing.expectEqual(header.stream_identifier, @as(u32, decoded.stream_identifier)) catch |err| {
            std.debug.print("{s}/{s}: codec stream identifier\n", .{ fixture.category, fixture.name });
            return err;
        };

        // And the codec must render back the octets it read.
        var rendered: [header_octets]u8 = undefined;
        _ = try decoded.render(&rendered);
        std.testing.expectEqualSlices(u8, wire[0..header_octets], &rendered) catch |err| {
            std.debug.print("{s}/{s}: render is not the inverse of parse\n", .{ fixture.category, fixture.name });
            return err;
        };

        const frame_value = parsed.value.object.get("frame").?;
        if (frame_value == .null) {
            failing += 1;
            const codes = parsed.value.object.get("error").?.array;
            try std.testing.expect(codes.items.len >= 1);
            continue;
        }

        valid += 1;
        const object = frame_value.object;
        std.testing.expectEqual(header.length, @as(u32, @intCast(object.get("length").?.integer))) catch |err| {
            std.debug.print("{s}/{s}: length\n", .{ fixture.category, fixture.name });
            return err;
        };
        std.testing.expectEqual(header.frame_type, @as(u8, @intCast(object.get("type").?.integer))) catch |err| {
            std.debug.print("{s}/{s}: type\n", .{ fixture.category, fixture.name });
            return err;
        };
        std.testing.expectEqual(header.flags, @as(u8, @intCast(object.get("flags").?.integer))) catch |err| {
            std.debug.print("{s}/{s}: flags\n", .{ fixture.category, fixture.name });
            return err;
        };
        std.testing.expectEqual(header.stream_identifier, @as(u32, @intCast(object.get("stream_identifier").?.integer))) catch |err| {
            std.debug.print("{s}/{s}: stream identifier\n", .{ fixture.category, fixture.name });
            return err;
        };
        std.testing.expectEqual(header_octets + header.length, @as(u32, @intCast(wire.len))) catch |err| {
            std.debug.print("{s}/{s}: wire length against declared length\n", .{ fixture.category, fixture.name });
            return err;
        };
    }

    try std.testing.expectEqual(@as(u32, 12), valid);
    try std.testing.expectEqual(@as(u32, 22), failing);
}

test "no valid fixture is rejected, and every rejection is one the fixture allows" {
    const allocator = std.testing.allocator;

    var caught: u32 = 0;
    var uncaught: u32 = 0;
    for (fixtures) |fixture| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture.json, .{});
        defer parsed.deinit();

        var buffer: [wire_max]u8 = undefined;
        const hex = parsed.value.object.get("wire").?.string;
        const wire = try std.fmt.hexToBytes(&buffer, hex);
        const header = try frame.Header.parse(wire);

        const expects_error = parsed.value.object.get("frame").? == .null;
        if (!expects_error) {
            // A frame the corpus calls well-formed must survive validation.
            header.validate(max_frame_size) catch |err| {
                std.debug.print("{s}/{s}: rejected a valid frame as {t}\n", .{
                    fixture.category, fixture.name, err,
                });
                return err;
            };
            continue;
        }

        header.validate(max_frame_size) catch |err| {
            // The code has to be one the fixture accepts. Some name more than
            // one: push_promise-frame-padding allows PROTOCOL_ERROR or
            // FRAME_SIZE_ERROR, so a test demanding a single code would be
            // wrong about it and right about the other twenty-one.
            const got = @intFromEnum(frame.Header.errorCode(err));
            const codes = parsed.value.object.get("error").?.array;
            var accepted = false;
            for (codes.items) |code| {
                if (@as(u32, @intCast(code.integer)) == got) accepted = true;
            }
            if (!accepted) {
                std.debug.print("{s}/{s}: returned code {d}, fixture allows", .{
                    fixture.category, fixture.name, got,
                });
                for (codes.items) |code| std.debug.print(" {d}", .{code.integer});
                std.debug.print("\n", .{});
                return error.TestUnexpectedResult;
            }
            caught += 1;
            continue;
        };
        // Not caught by the header alone, which is expected for the rules that
        // live in a payload.
        uncaught += 1;
    }

    // Pinned so the split can only move deliberately, and it should only move
    // one way. The five still uncaught each need an octet of payload: the pad
    // length of a DATA and a HEADERS frame checked against what is left, the
    // parity and non-zeroness of a promised stream identifier, and a
    // WINDOW_UPDATE increment of zero.
    //
    // `push_promise-frame-padding` is caught here rather than there, because a
    // PADDED PUSH_PROMISE shorter than five octets cannot hold its pad length
    // and its promised stream. Its fixture accepts PROTOCOL_ERROR or
    // FRAME_SIZE_ERROR and this returns the second, which is the reason the
    // check above tests membership rather than equality.
    try std.testing.expectEqual(@as(u32, 17), caught);
    try std.testing.expectEqual(@as(u32, 5), uncaught);
}
