//! RFC 9113 sections 6.1 to 6.10: what follows the nine-octet header.
//!
//! ## Borrowed, never copied
//!
//! Every variable-length field is a slice of the payload the caller passed in,
//! so parsing a frame allocates nothing and copies nothing. The caller owns the
//! octets and decides how long they live, which is the same arrangement HPACK's
//! decoder uses for a literal that was not Huffman-coded.
//!
//! ## What this layer adds to `Header.validate`
//!
//! Three rules, and they are the three that need an octet of payload to decide:
//!
//!   - a pad length at least as long as the payload (sections 6.1, 6.2, 6.6);
//!   - a promised stream identifier that is zero or odd (sections 5.1.1, 6.6);
//!   - a `WINDOW_UPDATE` increment of zero (section 6.9).
//!
//! Everything else — the length against `SETTINGS_MAX_FRAME_SIZE`, per-type
//! fixed and minimum lengths, stream-identifier validity — was decided by the
//! header, and `parse` asserts it was, rather than checking twice.
//!
//! One thing the header cannot decide, and it is easy to think it can: its
//! minimum length bounds the *whole* payload, padding included, and the peer
//! chooses how much of that is padding. So a HEADERS frame long enough to hold
//! its priority fields can still pad them away. That check belongs here, after
//! the split, and it is a check rather than an assertion.
//!
//! ## Severity is not uniform, and this is where that bites
//!
//! `Header.severity` can answer for every header-level failure with the type
//! and stream identifier alone. Here it cannot: section 6.9 makes a zero
//! increment a *stream* error on a stream and a *connection* error on the
//! connection flow-control window, so the same rule has two answers depending
//! on where it fired. That is why this module has its own `severity` rather
//! than reusing the header's.

const std = @import("std");

const assert = std.debug.assert;

const Header = @import("Header.zig");

pub const ErrorCode = Header.ErrorCode;
pub const Severity = Header.Severity;

// Field widths come from `Header`, which slices its own minimum lengths by
// them. See the note there on why they are not redeclared here.
const pad_length_octets = Header.pad_length_octets;
const stream_identifier_octets = Header.stream_identifier_octets;
const error_code_octets = Header.error_code_octets;
const priority_fields_octets = Header.priority_fields_octets;
const ping_payload_octets = Header.ping_payload_octets;
const settings_entry_octets = Header.settings_entry_octets;
/// Section 6.9's increment reserves its high bit exactly as a stream
/// identifier does, and is the same width.
const window_increment_octets = Header.window_increment_octets;

comptime {
    assert(window_increment_octets == stream_identifier_octets);
    assert(settings_entry_octets == 2 + 4);
}

pub const Error = error{
    /// Padding that does not leave the payload's fixed fields intact.
    ///
    /// Section 6.1 states the floor for DATA: padding at least the length of
    /// the frame payload is an error. HEADERS and PUSH_PROMISE carry fields
    /// *between* the pad length and the padding — the priority fields, the
    /// promised stream identifier — and padding that swallows those is the
    /// same error for the same reason.
    ///
    /// The header cannot catch this. Its minimum length bounds the whole
    /// payload including the padding, and the peer chooses how much of that is
    /// padding afterwards.
    Padding,
    /// A promised stream identifier of zero, or an odd one. Section 5.1.1
    /// reserves even identifiers for streams a server initiates, and only a
    /// server sends PUSH_PROMISE, so this holds whichever end is parsing.
    PromisedStream,
    /// A flow-control window increment of zero (section 6.9).
    ZeroIncrement,
};

/// The code a peer should be sent. All three rules here are PROTOCOL_ERROR;
/// they differ in how far they reach, not in what they are called.
pub fn errorCode(err: Error) ErrorCode {
    return switch (err) {
        error.Padding, error.PromisedStream, error.ZeroIncrement => .protocol_error,
    };
}

/// How far a failure reaches.
///
/// Section 6.9 is the reason this takes a header: a zero increment is a stream
/// error on a stream and a connection error on the connection flow-control
/// window, so the rule alone does not decide it.
pub fn severity(header: Header, err: Error) Severity {
    // Each rule belongs to the types that can break it, and asking about a
    // pairing that cannot happen is a caller's bug rather than an answer.
    if (err == error.PromisedStream) assert(header.frame_type == .push_promise);
    if (err == error.ZeroIncrement) assert(header.frame_type == .window_update);
    return switch (err) {
        // Sections 6.1 and 6.6 say connection error in as many words, and
        // section 5.1.1 does for an unexpected stream identifier.
        error.Padding, error.PromisedStream => .connection,
        error.ZeroIncrement => if (header.stream_identifier == 0) .connection else .stream,
    };
}

pub const Priority = struct {
    exclusive: bool,
    stream_dependency: u31,
    /// The octet as it appears on the wire, which is *not* the weight.
    ///
    /// Section 6.3: "Add one to the value to obtain a weight between 1 and
    /// 256." So the octet runs 0 to 255 and the weight runs 1 to 256, which is
    /// why `weight` is a method returning a wider integer rather than this
    /// field under a friendlier name. Section 5.3 deprecates prioritization
    /// altogether, but the octets still arrive and still have to be read
    /// correctly.
    weight_octet: u8,

    /// The priority weight, 1 to 256 (section 6.3). Wider than the octet it
    /// derives from, because 256 does not fit in one.
    pub fn weight(priority: Priority) u16 {
        return @as(u16, priority.weight_octet) + 1;
    }
};

pub const Data = struct {
    data: []const u8,
    padding: []const u8,
};

pub const Headers = struct {
    /// Present only when the PRIORITY flag is set.
    priority: ?Priority,
    /// A field block fragment (section 4.3), for HPACK to decode. Framing does
    /// not look inside it.
    fragment: []const u8,
    padding: []const u8,
};

pub const RstStream = struct {
    error_code: ErrorCode,
};

pub const PushPromise = struct {
    promised_stream_identifier: u31,
    fragment: []const u8,
    padding: []const u8,
};

pub const Ping = struct {
    /// Borrowed, and typed by its length so a caller cannot pass eight octets
    /// of something else.
    opaque_data: *const [ping_payload_octets]u8,
};

pub const Goaway = struct {
    last_stream_identifier: u31,
    error_code: ErrorCode,
    /// Whatever the peer chose to send, which is opaque and may be empty.
    debug_data: []const u8,
};

pub const WindowUpdate = struct {
    /// Never zero: section 6.9 makes that an error, checked in `parse`.
    increment: u31,
};

pub const Continuation = struct {
    fragment: []const u8,
};

/// Section 6.5.1's parameters, as a view over the payload.
///
/// An iterator rather than an array, because the count is the peer's choice and
/// this package does not allocate. Unknown identifiers are handed back rather
/// than skipped: section 6.5.2 requires a receiver to ignore them, and ignoring
/// is the consumer's to do.
pub const Settings = struct {
    entries: []const u8,

    pub const Identifier = enum(u16) {
        header_table_size = 0x01,
        enable_push = 0x02,
        max_concurrent_streams = 0x03,
        initial_window_size = 0x04,
        max_frame_size = 0x05,
        max_header_list_size = 0x06,
        _,
    };

    pub const Entry = struct {
        identifier: Identifier,
        value: u32,
    };

    pub fn count(settings: Settings) u32 {
        assert(settings.entries.len % settings_entry_octets == 0);
        return @intCast(@divExact(settings.entries.len, settings_entry_octets));
    }

    pub fn get(settings: Settings, index: u32) Entry {
        assert(index < settings.count());
        const at = index * settings_entry_octets;
        const octets = settings.entries[at..][0..settings_entry_octets];
        return .{
            .identifier = @enumFromInt((@as(u16, octets[0]) << 8) | octets[1]),
            .value = (@as(u32, octets[2]) << 24) | (@as(u32, octets[3]) << 16) |
                (@as(u32, octets[4]) << 8) | octets[5],
        };
    }

    pub const Iterator = struct {
        settings: Settings,
        index: u32 = 0,

        pub fn next(iterator: *Iterator) ?Entry {
            const total = iterator.settings.count();
            assert(iterator.index <= total);
            // `>=` rather than `==`: `index` is a public field, so a caller can
            // set it past the end and `==` would walk off.
            if (iterator.index >= total) return null;
            const entry = iterator.settings.get(iterator.index);
            iterator.index += 1;
            return entry;
        }
    };

    pub fn iterate(settings: Settings) Iterator {
        return .{ .settings = settings };
    }
};

pub const Payload = union(enum) {
    data: Data,
    headers: Headers,
    priority: Priority,
    rst_stream: RstStream,
    settings: Settings,
    push_promise: PushPromise,
    ping: Ping,
    goaway: Goaway,
    window_update: WindowUpdate,
    continuation: Continuation,
    /// A type RFC 9113 does not define. Section 4.1 requires it be skipped by
    /// its declared length, so the octets are handed back unexamined.
    unknown: []const u8,
};

/// Parse the payload of a frame whose header already validated.
///
/// `payload` must be exactly `header.length` octets — the caller slices it by
/// the length the header declared, and that length was already checked against
/// `SETTINGS_MAX_FRAME_SIZE` and against the type's own rules. Both are
/// asserted rather than re-checked: a second check that could disagree with the
/// first is worse than one that cannot.
pub fn parse(header: Header, payload: []const u8) Error!Payload {
    assert(payload.len == header.length);
    // The header's own rules held, so every fixed field below fits.
    assert(header.validate(Header.max_frame_size_max) != error.FrameSize);

    return switch (header.frame_type) {
        .data => blk: {
            const split = try splitPadding(payload, header.has(.padded));
            break :blk .{ .data = .{ .data = split.body, .padding = split.padding } };
        },
        .headers => .{ .headers = try parseHeaders(header, payload) },
        .priority => blk: {
            assert(payload.len == priority_fields_octets);
            break :blk .{ .priority = readPriority(payload[0..priority_fields_octets]) };
        },
        .rst_stream => blk: {
            assert(payload.len == error_code_octets);
            break :blk .{ .rst_stream = .{
                .error_code = @enumFromInt(readU32(payload[0..error_code_octets])),
            } };
        },
        .settings => blk: {
            assert(payload.len % settings_entry_octets == 0);
            break :blk .{ .settings = .{ .entries = payload } };
        },
        .push_promise => .{ .push_promise = try parsePushPromise(header, payload) },
        .ping => blk: {
            assert(payload.len == ping_payload_octets);
            break :blk .{ .ping = .{ .opaque_data = payload[0..ping_payload_octets] } };
        },
        .goaway => blk: {
            assert(payload.len >= stream_identifier_octets + error_code_octets);
            break :blk .{ .goaway = .{
                .last_stream_identifier = readStreamIdentifier(payload[0..stream_identifier_octets]),
                .error_code = @enumFromInt(readU32(payload[stream_identifier_octets..][0..error_code_octets])),
                .debug_data = payload[stream_identifier_octets + error_code_octets ..],
            } };
        },
        .window_update => blk: {
            assert(payload.len == window_increment_octets);
            // The reserved bit is ignored here as it is in a stream
            // identifier (section 6.9).
            const increment = readStreamIdentifier(payload[0..window_increment_octets]);
            if (increment == 0) return error.ZeroIncrement;
            break :blk .{ .window_update = .{ .increment = increment } };
        },
        .continuation => .{ .continuation = .{ .fragment = payload } },
        _ => .{ .unknown = payload },
    };
}

/// Section 6.2: a pad length, the priority fields when the flag is set, the
/// field block fragment, and the padding.
fn parseHeaders(header: Header, payload: []const u8) Error!Headers {
    const split = try splitPadding(payload, header.has(.padded));
    var rest = split.body;
    var priority: ?Priority = null;
    if (header.has(.priority)) {
        // Checked, not asserted: `Header.validate`'s floor covered the payload
        // before the padding was taken out of it.
        if (rest.len < priority_fields_octets) return error.Padding;
        priority = readPriority(rest[0..priority_fields_octets]);
        rest = rest[priority_fields_octets..];
    }
    assert(rest.len <= payload.len);
    return .{ .priority = priority, .fragment = rest, .padding = split.padding };
}

/// Section 6.6: a pad length, the promised stream identifier, the field block
/// fragment, and the padding.
fn parsePushPromise(header: Header, payload: []const u8) Error!PushPromise {
    const split = try splitPadding(payload, header.has(.padded));
    // Same as HEADERS: the header's floor bounded the payload, and the padding
    // comes out of it afterwards.
    if (split.body.len < stream_identifier_octets) return error.Padding;

    const promised = readStreamIdentifier(split.body[0..stream_identifier_octets]);
    // Section 5.1.1: a server's streams are even-numbered, and zero never
    // establishes a stream. Only a server sends PUSH_PROMISE, so this holds
    // whichever end is parsing.
    if (promised == 0 or promised % 2 != 0) return error.PromisedStream;
    assert(promised % 2 == 0);
    return .{
        .promised_stream_identifier = promised,
        .fragment = split.body[stream_identifier_octets..],
        .padding = split.padding,
    };
}

const Padded = struct {
    body: []const u8,
    padding: []const u8,
};

/// Split a payload into its body and its padding.
///
/// The comparison is a subtraction, not an addition. `pad_length` is the peer's
/// octet and can be anything a `u8` holds; `body_length + pad_length` would be
/// the third time in this package that adding an attacker's number to one of
/// ours before comparing was the bug. Section 6.1's rule — padding at least the
/// payload's length is an error — is exactly `pad_length > rest.len`, because
/// the pad length octet is itself part of that payload.
fn splitPadding(payload: []const u8, padded: bool) Error!Padded {
    if (!padded) return .{ .body = payload, .padding = payload[payload.len..] };
    // `Header.validate` established the pad length octet is there.
    assert(payload.len >= pad_length_octets);

    const pad_length = payload[0];
    const rest = payload[pad_length_octets..];
    if (pad_length > rest.len) return error.Padding;

    assert(pad_length <= rest.len);
    const body_length = rest.len - pad_length;
    return .{ .body = rest[0..body_length], .padding = rest[body_length..] };
}

fn readPriority(octets: *const [priority_fields_octets]u8) Priority {
    return .{
        .exclusive = octets[0] & 0x80 != 0,
        .stream_dependency = readStreamIdentifier(octets[0..stream_identifier_octets]),
        .weight_octet = octets[stream_identifier_octets],
    };
}

fn readU32(octets: *const [4]u8) u32 {
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) | octets[3];
}

/// A stream identifier, with section 4.1's reserved bit masked off. The same
/// masking applies to a stream dependency and to a window increment, both of
/// which reserve their high bit the same way.
fn readStreamIdentifier(octets: *const [stream_identifier_octets]u8) u31 {
    const value = readU32(octets) & Header.stream_identifier_mask;
    // The negative space: the reserved bit did not survive into the value. It
    // is the same assertion `Header.parse` makes about the same masking, and
    // it is the only thing between a reserved-bit slip and a promised stream
    // identifier flipping parity.
    assert(value & ~Header.stream_identifier_mask == 0);
    return @intCast(value);
}

const testing = std.testing;

/// Parse a whole frame, header and payload, the way a caller would.
fn parseFrame(wire: []const u8) !Payload {
    const header = try Header.parse(wire);
    try header.validate(Header.max_frame_size_min);
    return parse(header, wire[Header.octets..][0..header.length]);
}

test "a padded payload splits into body and padding" {
    // DATA, PADDED, stream 1: pad length 3, "hi", three octets of padding.
    const wire = [_]u8{ 0, 0, 6, 0x00, 0x08, 0, 0, 0, 1, 3, 'h', 'i', 0, 0, 0 };
    const payload = try parseFrame(&wire);
    try testing.expectEqualStrings("hi", payload.data.data);
    try testing.expectEqual(@as(usize, 3), payload.data.padding.len);
}

test "an unpadded payload is all body, and its padding is empty rather than null" {
    const wire = [_]u8{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 1, 'h', 'i' };
    const payload = try parseFrame(&wire);
    try testing.expectEqualStrings("hi", payload.data.data);
    try testing.expectEqual(@as(usize, 0), payload.data.padding.len);
}

test "padding at least the payload length is refused, at the boundary" {
    // Payload is four octets: a pad length and three more. A pad length of
    // three consumes them exactly and is legal; four is not.
    const legal = [_]u8{ 0, 0, 4, 0x00, 0x08, 0, 0, 0, 1, 3, 0, 0, 0 };
    const payload = try parseFrame(&legal);
    try testing.expectEqual(@as(usize, 0), payload.data.data.len);
    try testing.expectEqual(@as(usize, 3), payload.data.padding.len);

    const illegal = [_]u8{ 0, 0, 4, 0x00, 0x08, 0, 0, 0, 1, 4, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&illegal));

    // And a pad length no octet count could satisfy.
    const absurd = [_]u8{ 0, 0, 4, 0x00, 0x08, 0, 0, 0, 1, 0xff, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&absurd));
}

test "a pad length of zero is legal and costs one octet" {
    // The RFC notes this explicitly: a frame can be made one octet longer by
    // including a zero pad length.
    const wire = [_]u8{ 0, 0, 3, 0x00, 0x08, 0, 0, 0, 1, 0, 'h', 'i' };
    const payload = try parseFrame(&wire);
    try testing.expectEqualStrings("hi", payload.data.data);
    try testing.expectEqual(@as(usize, 0), payload.data.padding.len);
}

test "HEADERS carries priority only when the flag is set" {
    const bare = [_]u8{ 0, 0, 2, 0x01, 0x00, 0, 0, 0, 1, 'h', 'i' };
    const without = try parseFrame(&bare);
    try testing.expectEqual(@as(?Priority, null), without.headers.priority);
    try testing.expectEqualStrings("hi", without.headers.fragment);

    // PRIORITY flag: exclusive, dependency 20, weight 10, then the fragment.
    const prioritized = [_]u8{ 0, 0, 7, 0x01, 0x20, 0, 0, 0, 3, 0x80, 0, 0, 20, 10, 'h', 'i' };
    const with = try parseFrame(&prioritized);
    try testing.expect(with.headers.priority.?.exclusive);
    try testing.expectEqual(@as(u31, 20), with.headers.priority.?.stream_dependency);
    // The wire octet is 10 and the weight is 11: section 6.3 adds one.
    try testing.expectEqual(@as(u8, 10), with.headers.priority.?.weight_octet);
    try testing.expectEqual(@as(u16, 11), with.headers.priority.?.weight());
    try testing.expectEqualStrings("hi", with.headers.fragment);
}

test "a promised stream identifier must be even and non-zero" {
    // PUSH_PROMISE on stream 1 promising stream 12.
    const even = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 12, 'h', 'i' };
    const payload = try parseFrame(&even);
    try testing.expectEqual(@as(u31, 12), payload.push_promise.promised_stream_identifier);
    try testing.expectEqualStrings("hi", payload.push_promise.fragment);

    const odd = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 11, 'h', 'i' };
    try testing.expectError(error.PromisedStream, parseFrame(&odd));

    const zero = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 'h', 'i' };
    try testing.expectError(error.PromisedStream, parseFrame(&zero));

    // The reserved bit does not make an even identifier odd.
    const reserved = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0x80, 0, 0, 12, 'h', 'i' };
    const masked = try parseFrame(&reserved);
    try testing.expectEqual(@as(u31, 12), masked.push_promise.promised_stream_identifier);
}

test "a window increment of zero is refused, and its severity depends on the stream" {
    const on_stream = [_]u8{ 0, 0, 4, 0x08, 0x00, 0, 0, 0, 5, 0, 0, 0, 0 };
    try testing.expectError(error.ZeroIncrement, parseFrame(&on_stream));
    const stream_header = try Header.parse(&on_stream);
    try testing.expectEqual(Severity.stream, severity(stream_header, error.ZeroIncrement));

    // Section 6.9: on the connection flow-control window it ends the
    // connection instead.
    const on_connection = [_]u8{ 0, 0, 4, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.ZeroIncrement, parseFrame(&on_connection));
    const connection_header = try Header.parse(&on_connection);
    try testing.expectEqual(Severity.connection, severity(connection_header, error.ZeroIncrement));

    // A non-zero increment parses, with the reserved bit ignored.
    const fine = [_]u8{ 0, 0, 4, 0x08, 0x00, 0, 0, 0, 5, 0x80, 0, 0x03, 0xe8 };
    const payload = try parseFrame(&fine);
    try testing.expectEqual(@as(u31, 1000), payload.window_update.increment);
}

test "SETTINGS iterates its parameters and keeps unknown identifiers" {
    const wire = [_]u8{
        0, 0, 12, 0x04, 0x00, 0, 0, 0, 0,
        0x00, 0x01, 0x00, 0x00, 0x20, 0x00, // HEADER_TABLE_SIZE = 8192
        0xff, 0xff, 0x00, 0x00, 0x00, 0x07, // an identifier RFC 9113 does not define
    };
    const payload = try parseFrame(&wire);
    try testing.expectEqual(@as(u32, 2), payload.settings.count());

    var iterator = payload.settings.iterate();
    const first = iterator.next().?;
    try testing.expectEqual(Settings.Identifier.header_table_size, first.identifier);
    try testing.expectEqual(@as(u32, 8192), first.value);

    // Section 6.5.2 says a receiver ignores an unknown identifier; ignoring is
    // the consumer's to do, so it arrives rather than disappearing.
    const second = iterator.next().?;
    try testing.expectEqual(@as(u16, 0xffff), @intFromEnum(second.identifier));
    try testing.expectEqual(@as(u32, 7), second.value);
    try testing.expectEqual(@as(?Settings.Entry, null), iterator.next());
}

test "GOAWAY's debug data is optional" {
    const bare = [_]u8{ 0, 0, 8, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 9 };
    const payload = try parseFrame(&bare);
    try testing.expectEqual(@as(u31, 30), payload.goaway.last_stream_identifier);
    try testing.expectEqual(ErrorCode.compression_error, payload.goaway.error_code);
    try testing.expectEqual(@as(usize, 0), payload.goaway.debug_data.len);

    const with_data = [_]u8{ 0, 0, 10, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 9, 'h', 'i' };
    const verbose = try parseFrame(&with_data);
    try testing.expectEqualStrings("hi", verbose.goaway.debug_data);
}

test "an unknown type is handed back whole rather than examined" {
    const wire = [_]u8{ 0, 0, 3, 0xfa, 0xff, 0, 0, 0, 7, 1, 2, 3 };
    const payload = try parseFrame(&wire);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, payload.unknown);
}

test "every payload field borrows the caller's octets" {
    const wire = [_]u8{ 0, 0, 2, 0x09, 0x00, 0, 0, 0, 1, 'h', 'i' };
    const payload = try parseFrame(&wire);
    // The fragment is the wire's own octets, not a copy of them.
    try testing.expectEqual(@intFromPtr(&wire[Header.octets]), @intFromPtr(payload.continuation.fragment.ptr));
}

test "error codes and severities are what a peer is sent" {
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.Padding));
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.PromisedStream));
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.ZeroIncrement));

    // Each rule is asked about a frame that can actually break it.
    const data: Header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_identifier = 1 };
    try testing.expectEqual(Severity.connection, severity(data, error.Padding));

    const promise: Header = .{ .length = 0, .frame_type = .push_promise, .flags = 0, .stream_identifier = 1 };
    try testing.expectEqual(Severity.connection, severity(promise, error.PromisedStream));
}

test "padding may not swallow the fields that follow it" {
    // The header's minimum length bounds the whole payload, padding included,
    // and the peer picks the split afterwards. A HEADERS frame long enough to
    // hold its priority fields can still pad them away — which used to be an
    // assertion here, so a peer could panic a safe build with fifteen octets
    // and feed a fast one padding octets as a stream dependency.
    //
    // PADDED|PRIORITY, length 6, pad length 5: the header's floor is exactly 6,
    // so it passes, and nothing is left for the five priority octets.
    const headers = [_]u8{ 0, 0, 6, 0x01, 0x28, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&headers));

    // One octet more of payload and one less of padding is the boundary, and
    // it is legal: five octets of priority fields and an empty fragment.
    const exact = [_]u8{ 0, 0, 7, 0x01, 0x28, 0, 0, 0, 1, 1, 0, 0, 0, 20, 9, 0 };
    const payload = try parseFrame(&exact);
    try testing.expectEqual(@as(u31, 20), payload.headers.priority.?.stream_dependency);
    try testing.expectEqual(@as(usize, 0), payload.headers.fragment.len);
    try testing.expectEqual(@as(usize, 1), payload.headers.padding.len);

    // PUSH_PROMISE is the same shape: floor 5, pad length 4, nothing left for
    // the promised stream identifier.
    const promise = [_]u8{ 0, 0, 5, 0x05, 0x08, 0, 0, 0, 1, 4, 0, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&promise));

    // And every pad length in between, for both, rather than only the extreme.
    var pad: u8 = 1;
    while (pad <= 5) : (pad += 1) {
        var wire = [_]u8{ 0, 0, 7, 0x01, 0x28, 0, 0, 0, 1, pad, 0, 0, 0, 20, 9, 0 };
        wire[9] = pad;
        const result = parseFrame(&wire);
        if (pad + priority_fields_octets > 6) {
            try testing.expectError(error.Padding, result);
        } else {
            _ = try result;
        }
    }
}
