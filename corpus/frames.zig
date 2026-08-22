//! Fixture integrity for http2jp/http2-frame-test-case.
//!
//! See corpus/README.md for what is vendored and why. This file is the gate for
//! #2, and today it is only half of one: there is no frame codec yet, so what
//! it checks is that every fixture's declared metadata agrees with its own wire
//! octets. When the codec lands, these same fixtures get decoded by it and this
//! grows into the conformance test proper.
//!
//! That is not a placeholder in the sense of doing nothing. It pins the corpus
//! against a corrupted vendor or a bad checkout, and it writes down a reading of
//! the nine-octet frame header — length, type, flags, stream identifier — in a
//! place independent of `src/`, so the codec is built against an expectation
//! that already exists rather than one invented alongside it.
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
const Header = struct {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream: u32,
};

fn readHeader(wire: []const u8) Header {
    std.debug.assert(wire.len >= header_octets);
    return .{
        .length = (@as(u32, wire[0]) << 16) | (@as(u32, wire[1]) << 8) | wire[2],
        .frame_type = wire[3],
        .flags = wire[4],
        // The high bit is reserved and ignored on receipt (section 4.1), which
        // is a decision to encode rather than a bit to drop and forget.
        .stream = (@as(u32, wire[5] & 0x7f) << 24) | (@as(u32, wire[6]) << 16) |
            (@as(u32, wire[7]) << 8) | wire[8],
    };
}

const wire_max = 4096;

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

        const frame = parsed.value.object.get("frame").?;
        if (frame == .null) {
            // An error case: the payload is absent and at least one error code
            // is named. Section 7's codes are what the codec will have to
            // return, so a case naming none would be untestable.
            failing += 1;
            const codes = parsed.value.object.get("error").?.array;
            try std.testing.expect(codes.items.len >= 1);
            continue;
        }

        valid += 1;
        const object = frame.object;
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
        std.testing.expectEqual(header.stream, @as(u32, @intCast(object.get("stream_identifier").?.integer))) catch |err| {
            std.debug.print("{s}/{s}: stream identifier\n", .{ fixture.category, fixture.name });
            return err;
        };
        // A valid fixture's wire is exactly its header and its declared
        // payload, which is the invariant the codec's length check will rest on.
        std.testing.expectEqual(header_octets + header.length, @as(u32, @intCast(wire.len))) catch |err| {
            std.debug.print("{s}/{s}: wire length against declared length\n", .{ fixture.category, fixture.name });
            return err;
        };
    }

    // The fixtures are embedded, so an empty set would otherwise pass in
    // silence. All ten frame types have a valid case; see corpus/README.md.
    try std.testing.expectEqual(@as(u32, 12), valid);
    try std.testing.expectEqual(@as(u32, 22), failing);
}
