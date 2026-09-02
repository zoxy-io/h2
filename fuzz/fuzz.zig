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

const frame = h2.frame;

/// The oracle's own assert, always on.
///
/// Deliberately not `std.debug.assert` and deliberately not the library's
/// `-Dassertions`-gated one. Every property these targets check is expressed as
/// an assertion, so an assertion the build can remove is a fuzz target the
/// build can turn into a crash-only fuzzer — and `zig build fuzz --fuzz
/// -Doptimize=ReleaseFast` is the natural way to actually fuzz. That is the
/// same failure this package's `-Dassertions` option exists to fix, one
/// directory over.
///
/// Note the library's *internal* assertions are a separate matter: those follow
/// `-Dassertions`, and fuzzing with them off is a legitimate thing to do — it
/// checks that the decoders reject on their own rather than on an invariant
/// check. What must not vanish is the oracle.
fn assert(ok: bool) void {
    if (!ok) @panic("fuzz: oracle assertion failed");
}

/// Inputs are capped so a failing case stays small enough to read.
const input_max = 1024;

/// Frames offered to one field block assembler in a sequence.
const frames_per_sequence_max = 24;

test "fuzz: frame header" {
    try std.testing.fuzz({}, fuzzFrameHeader, .{});
}

/// Parse, render and validate a frame header drawn from arbitrary octets.
///
/// Three properties. Parsing nine octets never fails and never panics — every
/// bit pattern is a syntactically valid header, because the type and flag
/// fields are deliberately open. Rendering reproduces the octets it read,
/// except the reserved bit, which section 4.1 requires be ignored on receipt
/// and sent as zero. And `validate` reaches a decision for every header and
/// every legal `SETTINGS_MAX_FRAME_SIZE`, rather than asserting its way out of
/// one.
fn fuzzFrameHeader(_: void, smith: *std.testing.Smith) !void {
    var wire: [frame.Header.octets]u8 = undefined;
    smith.bytes(&wire);

    const header = frame.Header.parse(&wire) catch unreachable;

    var rendered: [frame.Header.octets]u8 = undefined;
    _ = frame.Header.render(header, &rendered) catch unreachable;
    var expected = wire;
    // The one octet that legitimately differs: the reserved bit is ignored on
    // receipt and sent as zero. The mask is the codec's own, so this cannot
    // drift from what `parse` actually does.
    expected[5] &= @truncate(frame.Header.stream_identifier_mask >> 24);
    assert(std.mem.eql(u8, &expected, &rendered));

    // Any value a peer could legally advertise, so the bound itself is drawn
    // rather than fixed at the floor.
    const span = frame.Header.max_frame_size_max - frame.Header.max_frame_size_min;
    const max_frame_size = frame.Header.max_frame_size_min + smith.value(u32) % (span + 1);
    if (header.validate(max_frame_size)) {
        // A header that validates is one whose length fits the bound, whatever
        // else it says.
        assert(header.length <= max_frame_size);
    } else |err| {
        const code = @intFromEnum(frame.Header.errorCode(err));
        assert(code == 0x01 or code == 0x06);
        // Severity is decidable for every failure, and a stream error needs a
        // stream: nothing on stream zero may be answered with RST_STREAM.
        const how = header.severity(err);
        if (header.stream_identifier == 0) assert(how == .connection);
        if (err == error.Protocol) assert(how == .connection);
    }
}

test "fuzz: frame payload" {
    try std.testing.fuzz({}, fuzzFramePayload, .{});
}

/// Draw a whole frame and parse both layers.
///
/// The header target above stops at nine octets, so nothing reached the payload
/// codec — and the first bug found there was exactly the shape this catches: a
/// HEADERS frame whose header passes its minimum-length rule and whose padding
/// then swallows the priority fields, which was an assertion rather than a
/// check. Fifteen octets, and the assertion is its own oracle.
///
/// Beyond reject-or-parse: every slice handed back must lie inside the payload
/// it was parsed from. A codec that borrows is only safe if it borrows from
/// where it says it does.
fn fuzzFramePayload(_: void, smith: *std.testing.Smith) !void {
    var buffer: [input_max]u8 = undefined;
    const length = smith.slice(&buffer);
    if (length < frame.Header.octets) return;

    // Make the declared length agree with the octets actually drawn, so the
    // draw spends its entropy on payload shapes rather than on lengths that
    // cannot be satisfied.
    const body_length: u32 = @intCast(length - frame.Header.octets);
    buffer[0] = @truncate(body_length >> 16);
    buffer[1] = @truncate(body_length >> 8);
    buffer[2] = @truncate(body_length);

    const wire = buffer[0..length];
    const header = frame.Header.parse(wire) catch unreachable;
    assert(header.length == body_length);
    header.validate(frame.Header.max_frame_size_min) catch return;

    const body = wire[frame.Header.octets..][0..header.length];
    const payload = frame.payload.parse(header, body) catch |err| {
        // Severity is answerable for every failure this layer produces.
        _ = frame.payload.errorCode(err);
        return;
    };

    // Whatever parsed must render back to the octets it came from. A codec
    // that reads a frame it cannot write has lost something, and until the
    // padding became optional it had: an unpadded frame and a zero-padded one
    // both parsed to an empty padding slice and rendered as the same frame.
    // A rendered frame is never longer than the wire it parsed from — the
    // payload borrows those octets and the header is the same nine — which is
    // what makes the `catch unreachable` below a proof rather than a hope.
    if (payload != .unknown) {
        var rendered: [input_max]u8 = undefined;
        const sender_flags = header.flags & ~frame.payload.structuralFlags(&payload);
        const written = frame.payload.render(
            &payload,
            header.stream_identifier,
            sender_flags,
            &rendered,
        ) catch unreachable;
        assert(written == wire.len);
        assert(std.mem.eql(u8, rendered[0..written], wire));
    }

    // Everything borrowed points into the payload it came from.
    switch (payload) {
        .data => |data| {
            assertBorrowed(body, data.data);
            if (data.padding) |padding| assertBorrowed(body, padding);
        },
        .headers => |headers| {
            assertBorrowed(body, headers.fragment);
            if (headers.padding) |padding| assertBorrowed(body, padding);
        },
        .push_promise => |promise| {
            assertBorrowed(body, promise.fragment);
            if (promise.padding) |padding| assertBorrowed(body, padding);
            // Section 5.1.1, restated where a parse could get it wrong.
            assert(promise.promised_stream_identifier % 2 == 0);
            assert(promise.promised_stream_identifier != 0);
        },
        .goaway => |goaway| assertBorrowed(body, goaway.debug_data),
        .continuation => |continuation| assertBorrowed(body, continuation.fragment),
        .settings => |settings| {
            assertBorrowed(body, settings.entries);
            var iterator = settings.iterate();
            var seen: u32 = 0;
            while (iterator.next()) |_| seen += 1;
            assert(seen == settings.count());
        },
        .ping => |ping| assertBorrowed(body, ping.opaque_data),
        .window_update => |update| assert(update.increment != 0),
        .unknown => |octets| assertBorrowed(body, octets),
        .priority, .rst_stream => {},
    }
}

/// A slice lies within `owner`, empty ones included.
fn assertBorrowed(owner: []const u8, borrowed: []const u8) void {
    if (borrowed.len == 0) return;
    const owner_begin = @intFromPtr(owner.ptr);
    const begin = @intFromPtr(borrowed.ptr);
    assert(begin >= owner_begin);
    assert(begin + borrowed.len <= owner_begin + owner.len);
}

test "fuzz: field block assembly" {
    try std.testing.fuzz({}, fuzzBlockAssembly, .{});
}

/// Drive a sequence of drawn frames through the field block assembler.
///
/// The first thing in the package that holds state, so the properties are about
/// the state machine rather than one call: a failure always leaves nothing open,
/// a completed block never exceeds the buffer it was assembled in, and no block
/// spans more frames than the bound allows. The sequence matters — a
/// single-frame target could not reach the interleaving rules at all.
fn fuzzBlockAssembly(_: void, smith: *std.testing.Smith) !void {
    var assembly: [512]u8 = undefined;
    const frames_max: u32 = 1 + smith.value(u3);
    var assembler = frame.BlockAssembler.init(&assembly, frames_max);

    var offered: u32 = 0;
    while (offered < frames_per_sequence_max and !smith.eosWeightedSimple(10, 1)) {
        offered += 1;

        var wire: [input_max]u8 = undefined;
        const length = smith.slice(&wire);
        if (length < frame.Header.octets) continue;

        const body_length: u32 = @intCast(length - frame.Header.octets);
        wire[0] = @truncate(body_length >> 16);
        wire[1] = @truncate(body_length >> 8);
        wire[2] = @truncate(body_length);

        const header = frame.Header.parse(wire[0..length]) catch unreachable;
        header.validate(frame.Header.max_frame_size_min) catch continue;
        const body = wire[frame.Header.octets..][0..header.length];
        const parsed = frame.payload.parse(header, body) catch continue;

        const accepted = assembler.accept(header, &parsed) catch |err| {
            // Every failure ends the connection, and leaves nothing a caller
            // could keep feeding.
            assert(frame.BlockAssembler.severity(err) == .connection);
            assert(!assembler.isOpen());
            _ = frame.BlockAssembler.errorCode(err);
            return;
        };

        switch (accepted) {
            .passthrough => assert(!assembler.isOpen()),
            .fragment => assert(assembler.isOpen()),
            .block => |block| {
                // A finished block fits the buffer it was assembled in, and
                // the assembler is ready for the next one.
                assert(block.fragment.len <= assembly.len);
                assert(!assembler.isOpen());
                assertBorrowed(&assembly, block.fragment);
            },
        }
    }
}

/// Octets that classify differently across the four rules, so planting one is
/// always informative: the two colons and slashes part `.strict` from
/// `.minimal`, the controls part a value's `Delimiter` from its `Character`,
/// and `0x80` is the obs-text that must *not* be rejected.
const interesting_octets = "\x00\t\n\r A Z:/\"\x01\x7f\x80\xff!~";

test "fuzz: field syntax kernels agree" {
    try std.testing.fuzz({}, fuzzFieldSyntax, .{});
}

/// The vector sweep and the transcribed reference must be indistinguishable.
///
/// `syntax.zig` already proves at compile time that the two agree on every one
/// of the 256 octets, so what is left for a fuzzer is the *slice* walk: the
/// tail, the lengths that straddle a vector boundary, and which of several
/// rejected octets is the one reported. That last one is observable because a
/// name carrying both a misplaced colon and an uppercase letter returns a
/// different error depending on which comes first, so a sweep that found *some*
/// rejected octet rather than the first is caught here.
///
/// The input is built rather than drawn flat, and the difference matters. Drawn
/// octets reject within the first few almost always, which leaves the tail loop
/// and every long accepting run unreached — so the base is an octet all four
/// rules accept, and faults are then planted at drawn positions on top of it.
fn fuzzFieldSyntax(_: void, smith: *std.testing.Smith) !void {
    var text: [input_max]u8 = undefined;
    const length = smith.index(text.len + 1);
    assert(length <= text.len);
    // The base octet has to be one all four rule sets accept, or the planted
    // faults would never be the first rejection and every case would collapse
    // to the same answer.
    @memset(text[0..length], 'a');

    if (length > 0) {
        var planted: usize = 0;
        const faults = smith.index(faults_max + 1);
        while (planted < faults) : (planted += 1) {
            const position = smith.index(length);
            assert(position < length);
            text[position] = interesting_octets[smith.index(interesting_octets.len)];
        }
    }

    const subject = text[0..length];
    for ([_]h2.fields.Rules{ .minimal, .strict }) |rules| {
        try expectSameOutcome(
            h2.fields.NameError,
            h2.fields.syntax.validateNameReference(subject, rules),
            h2.fields.validateName(subject, rules),
        );
        try expectSameOutcome(
            h2.fields.ValueError,
            h2.fields.syntax.validateValueReference(subject, rules),
            h2.fields.validateValue(subject, rules),
        );
    }
}

/// Faults planted in one drawn run. Three is enough for the orderings that
/// decide which error comes back, and small enough that a failing case is
/// readable.
const faults_max = 3;

comptime {
    // A fault has to have somewhere to go: the generator plants at a drawn
    // index into a run of at most `input_max` octets.
    assert(faults_max <= input_max);
}

/// Two results of the same error set are the same result: both accepted, or
/// both rejected with the same error. Written out because the payload is
/// `void`, so `expectEqual` on the unions themselves compares nothing.
fn expectSameOutcome(comptime Set: type, reference: Set!void, kernel: Set!void) !void {
    const expected: ?Set = if (reference) |_| null else |err| err;
    const actual: ?Set = if (kernel) |_| null else |err| err;
    try std.testing.expectEqual(expected, actual);
}

/// Names drawn for the message-validator target: every pseudo-header including
/// one that is never defined, both connection-specific spellings that matter
/// most for a downgrade, `te`, and ordinary fields.
const drawn_names = [_][]const u8{
    ":method",   ":scheme", ":authority",        ":path",   ":status",
    ":protocol", ":bogus",  "transfer-encoding", "upgrade", "connection",
    "te",        "accept",  "cookie",            "host",    "x-forwarded-for",
};

/// Values chosen so that every rule keyed on a value is reachable at a useful
/// rate — CONNECT and its case-sensitivity, an http-like scheme in both cases,
/// an empty value, `te: trailers` in both cases.
const drawn_values = [_][]const u8{
    "GET",       "CONNECT",             "connect",   "OPTIONS",  "https",
    "HTTPS",     "http",                "ftp",       "",         "/",
    "*",         "200",                 "trailers",  "TRAILERS", "gzip",
    "websocket", "www.example.com:443", "text/html",
};

/// Fields offered to one message validator. Short enough that a failing case is
/// readable, long enough to reach a repeat of every pseudo-header.
const message_fields_max: usize = 12;

comptime {
    // The "long enough" half of that sentence, which is a relation rather than
    // a number: a block has to be able to carry every pseudo-header once and
    // still have room to repeat one.
    assert(message_fields_max > std.enums.values(h2.fields.MessageValidator.Pseudo).len);
}

test "fuzz: message validator" {
    try std.testing.fuzz({}, fuzzMessageValidator, .{});
}

/// A field block a validator accepts must actually satisfy RFC 9113 section
/// 8.3, re-derived from the whole block rather than from the state machine.
///
/// The accept direction is the one checked, and the asymmetry is deliberate:
/// accepting a malformed message is the security failure — it is the message
/// that reaches an HTTP/1.1 upstream — while refusing a well-formed one is an
/// interoperability bug that the unit tests in `MessageValidator.zig` cover
/// case by case. Restating the reject direction here would mean writing the
/// whole rule set a second time to prove a weaker property.
///
/// Reject-or-parse still holds regardless: the validator's own assertions are
/// live in this build, so a state machine that reached an impossible state
/// fails here whichever way it answered.
fn fuzzMessageValidator(_: void, smith: *std.testing.Smith) !void {
    const fields = h2.fields;

    var block: [message_fields_max]h2.hpack.Field = undefined;
    const count = smith.index(block.len + 1);
    assert(count <= block.len);
    for (block[0..count]) |*offered| {
        offered.* = .{
            .name = drawn_names[smith.index(drawn_names.len)],
            .value = drawn_values[smith.index(drawn_values.len)],
        };
    }

    const options: fields.MessageValidator.Options = .{
        .kind = smith.value(fields.MessageValidator.Kind),
        .rules = smith.value(fields.syntax.Rules),
        .extended_connect = smith.value(bool),
    };

    var validator: fields.MessageValidator = .init(options);
    for (block[0..count]) |*offered| {
        validator.field(offered) catch return;
    }
    validator.finish() catch return;

    try expectWellFormed(options, block[0..count]);
}

/// The pseudo-header registry and its direction table, written out here rather
/// than read from `MessageValidator`.
///
/// The first version of this oracle called `fields.isPseudo`, `Pseudo.name()`
/// and `Pseudo.forRequest()` — the implementation's own tables — while its doc
/// comment claimed to re-derive the rules. It did not: changing `forRequest` to
/// `return true` makes the validator accept `:status` in a request, and that
/// oracle would have agreed, because it asked the broken function.
const oracle_pseudo = [_]struct { name: []const u8, request: bool }{
    .{ .name = ":method", .request = true },
    .{ .name = ":scheme", .request = true },
    .{ .name = ":authority", .request = true },
    .{ .name = ":path", .request = true },
    .{ .name = ":protocol", .request = true },
    .{ .name = ":status", .request = false },
};

/// RFC 9113 section 8.2.2's connection-specific fields, likewise written out.
const oracle_connection_specific = [_][]const u8{
    "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade",
};

/// Sections 8.3, 8.3.1, 8.3.2, 8.5, 8.2.2 and RFC 8441 section 4, checked over a
/// block the validator accepted.
fn expectWellFormed(
    options: h2.fields.MessageValidator.Options,
    block: []const h2.hpack.Field,
) !void {
    var seen = [_]bool{false} ** oracle_pseudo.len;
    var regular_seen = false;
    var connect = false;
    var http_scheme = false;
    var empty_path = false;

    for (block) |offered| {
        try std.testing.expect(offered.name.len >= 1);
        if (offered.name[0] != ':') {
            regular_seen = true;
            // Section 8.2.2.
            for (oracle_connection_specific) |forbidden| {
                try std.testing.expect(!std.mem.eql(u8, offered.name, forbidden));
            }
            // Section 8.2.2's exception, which names a request and no other
            // kind of block; RFC 5234 section 2.3 makes the value's spelling
            // case-insensitive.
            if (std.mem.eql(u8, offered.name, "te")) {
                try std.testing.expect(options.kind == .request);
                try std.testing.expect(std.ascii.eqlIgnoreCase(offered.value, "trailers"));
            }
            continue;
        }

        // Section 8.3: no pseudo-header after a regular field.
        try std.testing.expect(!regular_seen);

        var index: ?usize = null;
        for (oracle_pseudo, 0..) |candidate, position| {
            if (std.mem.eql(u8, offered.name, candidate.name)) index = position;
        }
        // Section 8.3: an undefined pseudo-header is malformed, so an accepted
        // block cannot contain one.
        const which = index orelse return error.TestUnexpectedResult;
        // Section 8.3: "The same pseudo-header field name MUST NOT appear more
        // than once in a field block."
        try std.testing.expect(!seen[which]);
        seen[which] = true;

        // Section 8.3: each direction's own, and none at all in a trailer.
        switch (options.kind) {
            .trailer => return error.TestUnexpectedResult,
            .request => try std.testing.expect(oracle_pseudo[which].request),
            .response => try std.testing.expect(!oracle_pseudo[which].request),
        }

        // Section 8.3.1's "exactly one valid value", less `:path`, whose
        // emptiness is the scheme's question.
        if (!std.mem.eql(u8, offered.name, ":path")) {
            try std.testing.expect(offered.value.len >= 1);
        }

        if (std.mem.eql(u8, offered.name, ":method")) {
            // RFC 9110 section 9.1: the method token is case-sensitive.
            connect = std.mem.eql(u8, offered.value, "CONNECT");
        } else if (std.mem.eql(u8, offered.name, ":scheme")) {
            // RFC 3986 section 3.1: schemes are not.
            http_scheme = std.ascii.eqlIgnoreCase(offered.value, "http") or
                std.ascii.eqlIgnoreCase(offered.value, "https");
        } else if (std.mem.eql(u8, offered.name, ":path")) {
            empty_path = offered.value.len == 0;
        } else if (std.mem.eql(u8, offered.name, ":protocol")) {
            // RFC 8441 section 4: negotiated, or it does not exist.
            try std.testing.expect(options.extended_connect);
        }
    }

    const extended = seen[indexOfPseudo(":protocol")];
    switch (options.kind) {
        .trailer => {},
        // Section 8.3.2.
        .response => try std.testing.expect(seen[indexOfPseudo(":status")]),
        .request => if (extended) {
            // RFC 8441 section 4: ":protocol" rides on CONNECT, and requires
            // the ":scheme" and ":path" that plain CONNECT forbids.
            try std.testing.expect(connect);
            try std.testing.expect(seen[indexOfPseudo(":scheme")]);
            try std.testing.expect(seen[indexOfPseudo(":path")]);
            try std.testing.expect(!(http_scheme and empty_path));
        } else if (connect) {
            // Section 8.5.
            try std.testing.expect(!seen[indexOfPseudo(":scheme")]);
            try std.testing.expect(!seen[indexOfPseudo(":path")]);
            try std.testing.expect(seen[indexOfPseudo(":authority")]);
        } else {
            // Section 8.3.1.
            try std.testing.expect(seen[indexOfPseudo(":method")]);
            try std.testing.expect(seen[indexOfPseudo(":scheme")]);
            try std.testing.expect(seen[indexOfPseudo(":path")]);
            try std.testing.expect(!(http_scheme and empty_path));
        },
    }
}

/// The position of a pseudo-header in `oracle_pseudo`, resolved at compile
/// time so a name that is not in the table is a build failure rather than a
/// test that quietly checks the wrong slot.
fn indexOfPseudo(comptime name: []const u8) usize {
    return comptime blk: {
        for (oracle_pseudo, 0..) |candidate, position| {
            if (std.mem.eql(u8, candidate.name, name)) break :blk position;
        }
        unreachable;
    };
}

test "the message oracle refuses what a broken validator would accept" {
    // The oracle above is only worth having if it disagrees with a wrong
    // validator, and its first version did not: it called the implementation's
    // own registry and direction table, so any bug in those was invisible to
    // it. These three blocks are the three defect classes that review found —
    // each is malformed, each would be accepted by a plausible break in the
    // validator, and the oracle must refuse each on its own tables.
    //
    // Pinned deterministically rather than left to the fuzz target. Reaching
    // any of them by drawing needs a block that is well-formed in every other
    // respect, which is a narrow target in a fifteen-by-eighteen name and value
    // space — ninety seconds of coverage-guided fuzzing did not find the first
    // one. A fuzzer that cannot reach a case does not test it.
    const request: h2.fields.MessageValidator.Options =
        .{ .kind = .request, .rules = .strict };
    const extended: h2.fields.MessageValidator.Options =
        .{ .kind = .request, .rules = .strict, .extended_connect = true };

    // Section 8.3: a response's pseudo-header in a request. Accepted if
    // `Pseudo.forRequest` returned true for everything.
    try expectOracleRefuses(request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":status", .value = "200" },
    });

    // RFC 8441 section 4: extended CONNECT without the `:scheme` and `:path` it
    // requires. Accepted if section 8.5's rules were read first.
    try expectOracleRefuses(extended, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":protocol", .value = "websocket" },
    });

    // Section 8.3.1 with RFC 3986 section 3.1: an empty `:path` under a scheme
    // spelled in uppercase. Accepted if the scheme comparison were
    // case-sensitive.
    try expectOracleRefuses(request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "HTTPS" },
        .{ .name = ":path", .value = "" },
    });
}

/// Both halves: the validator rejects the block today, and the oracle would
/// reject it even if the validator stopped.
fn expectOracleRefuses(
    options: h2.fields.MessageValidator.Options,
    block: []const h2.hpack.Field,
) !void {
    var validator: h2.fields.MessageValidator = .init(options);
    var rejected = false;
    for (block) |*offered| {
        validator.field(offered) catch {
            rejected = true;
            break;
        };
    }
    if (!rejected) {
        validator.finish() catch {
            rejected = true;
        };
    }
    try std.testing.expect(rejected);
    try std.testing.expectError(error.TestUnexpectedResult, expectWellFormed(options, block));
}
