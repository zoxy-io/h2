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
            // A frame the corpus calls well-formed must survive both layers.
            header.validate(max_frame_size) catch |err| {
                std.debug.print("{s}/{s}: header rejected a valid frame as {t}\n", .{
                    fixture.category, fixture.name, err,
                });
                return err;
            };
            const body = wire[frame.Header.octets..][0..header.length];
            _ = frame.payload.parse(header, body) catch |err| {
                std.debug.print("{s}/{s}: payload rejected a valid frame as {t}\n", .{
                    fixture.category, fixture.name, err,
                });
                return err;
            };
            continue;
        }

        const got: ?u32 = blk: {
            header.validate(max_frame_size) catch |err| {
                break :blk @intFromEnum(frame.Header.errorCode(err));
            };
            const body = wire[frame.Header.octets..][0..header.length];
            _ = frame.payload.parse(header, body) catch |err| {
                break :blk @intFromEnum(frame.payload.errorCode(err));
            };
            break :blk null;
        };

        if (got) |code| {
            // The code has to be one the fixture accepts. Some name more than
            // one: push_promise-frame-padding allows PROTOCOL_ERROR or
            // FRAME_SIZE_ERROR, so a test demanding a single code would be
            // wrong about it and right about the other twenty-one.
            const codes = parsed.value.object.get("error").?.array;
            var accepted = false;
            for (codes.items) |allowed| {
                if (@as(u32, @intCast(allowed.integer)) == code) accepted = true;
            }
            if (!accepted) {
                std.debug.print("{s}/{s}: returned code {d}, fixture allows", .{
                    fixture.category, fixture.name, code,
                });
                for (codes.items) |allowed| std.debug.print(" {d}", .{allowed.integer});
                std.debug.print("\n", .{});
                return error.TestUnexpectedResult;
            }
            caught += 1;
            continue;
        }

        std.debug.print("{s}/{s}: accepted a frame the corpus rejects\n", .{
            fixture.category, fixture.name,
        });
        uncaught += 1;
    }

    // Every error case the corpus carries, now that the payload layer exists.
    // Seventeen were reachable from the nine-octet header alone; the last five
    // needed an octet of payload each.
    try std.testing.expectEqual(@as(u32, 22), caught);
    try std.testing.expectEqual(@as(u32, 0), uncaught);
}

test "every valid fixture's payload decodes to the fields it declares" {
    const allocator = std.testing.allocator;

    var checked: u32 = 0;
    for (fixtures) |fixture| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture.json, .{});
        defer parsed.deinit();

        const frame_value = parsed.value.object.get("frame").?;
        if (frame_value == .null) continue;

        var buffer: [wire_max]u8 = undefined;
        const hex = parsed.value.object.get("wire").?.string;
        const wire = try std.fmt.hexToBytes(&buffer, hex);
        const header = try frame.Header.parse(wire);
        const body = wire[frame.Header.octets..][0..header.length];
        const payload = try frame.payload.parse(header, body);

        const want = frame_value.object.get("frame_payload").?.object;
        checkPayload(&want, &payload) catch |err| {
            std.debug.print("{s}/{s}: payload\n", .{ fixture.category, fixture.name });
            return err;
        };
        checked += 1;
    }
    try std.testing.expectEqual(@as(u32, 12), checked);
}

/// Compare one decoded payload against what the fixture says it holds.
///
/// The corpus records a `frame_payload` for every valid frame and nothing read
/// it until now, which meant the whole payload half of the corpus was vendored
/// and unspent.
fn checkPayload(want: *const std.json.ObjectMap, got: *const frame.Payload) !void {
    switch (got.*) {
        .data => |data| {
            try std.testing.expectEqualStrings(want.get("data").?.string, data.data);
            try expectPadding(want, data.padding);
        },
        .headers => |headers| {
            try expectFragment(want, headers.fragment);
            try expectPadding(want, headers.padding);
            if (want.get("stream_dependency").? == .null) {
                try std.testing.expectEqual(@as(?frame.payload.Priority, null), headers.priority);
            } else {
                try expectPriority(want, headers.priority.?);
            }
        },
        .priority => |priority| try expectPriority(want, priority),
        .rst_stream => |rst| {
            try std.testing.expectEqual(
                @as(u32, @intCast(want.get("error_code").?.integer)),
                @intFromEnum(rst.error_code),
            );
        },
        .settings => |settings| {
            const entries = want.get("settings").?.array;
            try std.testing.expectEqual(@as(u32, @intCast(entries.items.len)), settings.count());
            var iterator = settings.iterate();
            for (entries.items) |entry| {
                const pair = entry.array;
                const decoded = iterator.next().?;
                try std.testing.expectEqual(
                    @as(u16, @intCast(pair.items[0].integer)),
                    @intFromEnum(decoded.identifier),
                );
                try std.testing.expectEqual(
                    @as(u32, @intCast(pair.items[1].integer)),
                    decoded.value,
                );
            }
            try std.testing.expectEqual(@as(?frame.payload.Settings.Entry, null), iterator.next());
        },
        .push_promise => |promise| {
            try std.testing.expectEqual(
                @as(u31, @intCast(want.get("promised_stream_id").?.integer)),
                promise.promised_stream_identifier,
            );
            try expectFragment(want, promise.fragment);
            try expectPadding(want, promise.padding);
        },
        .ping => |ping| {
            try std.testing.expectEqualStrings(want.get("opaque_data").?.string, ping.opaque_data);
        },
        .goaway => |goaway| {
            try std.testing.expectEqual(
                @as(u31, @intCast(want.get("last_stream_id").?.integer)),
                goaway.last_stream_identifier,
            );
            try std.testing.expectEqual(
                @as(u32, @intCast(want.get("error_code").?.integer)),
                @intFromEnum(goaway.error_code),
            );
            try std.testing.expectEqualStrings(
                want.get("additional_debug_data").?.string,
                goaway.debug_data,
            );
        },
        .window_update => |update| {
            try std.testing.expectEqual(
                @as(u31, @intCast(want.get("window_size_increment").?.integer)),
                update.increment,
            );
        },
        .continuation => |continuation| try expectFragment(want, continuation.fragment),
        .unknown => return error.TestUnexpectedResult,
    }
}

fn expectFragment(want: *const std.json.ObjectMap, fragment: []const u8) !void {
    try std.testing.expectEqualStrings(want.get("header_block_fragment").?.string, fragment);
}

/// The corpus records the *weight*, not the wire octet — RFC 9113 section 6.3
/// adds one. Both priority fixtures agree on that, which is how the codec's
/// original reading was caught.
fn expectPriority(want: *const std.json.ObjectMap, priority: frame.payload.Priority) !void {
    try std.testing.expectEqual(
        @as(u31, @intCast(want.get("stream_dependency").?.integer)),
        priority.stream_dependency,
    );
    try std.testing.expectEqual(
        @as(u16, @intCast(want.get("weight").?.integer)),
        priority.weight(),
    );
    try std.testing.expectEqual(want.get("exclusive").?.bool, priority.exclusive);
}

/// The corpus records a padding length and the padding itself, or null for
/// both when the frame is not padded.
fn expectPadding(want: *const std.json.ObjectMap, padding: []const u8) !void {
    const length = want.get("padding_length") orelse return;
    if (length == .null) {
        try std.testing.expectEqual(@as(usize, 0), padding.len);
        return;
    }
    try std.testing.expectEqual(@as(usize, @intCast(length.integer)), padding.len);
    try std.testing.expectEqualStrings(want.get("padding").?.string, padding);
}
