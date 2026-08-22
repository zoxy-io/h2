//! RFC 7541 section 5.2 and Appendix B: the fixed Huffman code.
//!
//! ## Decoding
//!
//! The decoder is the nibble automaton of Pajarola's "Fast Prefix Code
//! Processing" (2003), the construction nghttp2 has used since 2014. Each
//! input octet drives two table lookups, and each lookup may emit one symbol —
//! at most one, because the shortest code is five bits and four cannot finish
//! two of them.
//!
//! The table is `states_count` by 16 transitions of four octets, so about
//! 16 KiB: small enough to stay resident beside the rest of a proxy's working
//! set, which is the property that decides this design rather than raw
//! throughput. A 16-bit window (65536 entries, 256 KiB) consumes fewer lookups
//! per octet and measures faster in a tight loop, but it is an L2 resident, and
//! this code runs on a thread that is also serving thousands of connections.
//! See issue #1 for the measurements that decision is waiting on; the automaton
//! here is the reference any faster path must agree with.
//!
//! Validity comes free with the same lookup. Walking into the EOS leaf leads to
//! a failure state, and the failure state is absorbing and never accepting, so
//! a malformed string cannot be rescued by later input and needs no branch in
//! the loop to detect. Padding is checked by asking whether the state the input
//! ran out in is one whose path from the root is all ones and shorter than a
//! full octet — exactly section 5.2's two rules, answered by a table read.
//!
//! ## Encoding
//!
//! One code per input octet, accumulated in a 64-bit register and flushed a
//! byte at a time. A two-octet table (65536 entries, 512 KiB) buys 1.7-2.1x,
//! and costs more cache than this package is willing to spend for it.

const std = @import("std");

const assert = std.debug.assert;

const table = @import("huffman_codes.zig");

pub const Code = table.Code;
pub const eos = table.eos;
pub const bits_min = table.bits_min;
pub const bits_max = table.bits_max;

/// Longest run of padding bits a valid encoding can end with (RFC 7541
/// section 5.2): "a padding strictly longer than 7 bits MUST be treated as a
/// decoding error".
const padding_bits_max: u8 = 7;

comptime {
    // Padding shorter than an octet is the whole of section 5.2's second rule.
    assert(padding_bits_max < 8);
    // One symbol per nibble, which is what lets a `Transition` hold a single
    // symbol and what `walkNibble` asserts dynamically. Four bits cannot finish
    // two codes unless the shortest is four or fewer.
    assert(bits_min > 4);
    // A complete prefix code over `eos + 1` symbols has that many leaves and
    // one fewer internal node.
    assert(nodes_max == 2 * (@as(u16, eos) + 1) - 1);
    // Every state is an internal node, plus one for failure. A full binary
    // tree with L leaves has L - 1 internal nodes, so 2L - 1 total.
    assert(states_max == @divExact(nodes_max - 1, 2) + 1);
}

/// One nibble's transition. Four octets, so a row is 64 and the whole table is
/// `states_count` times that.
const Transition = struct {
    next_state: u16,
    symbol: u8,
    emits: bool,

    /// A transition that goes nowhere and emits nothing, used to fill the
    /// table before the walk overwrites it.
    const blank: Transition = .{ .next_state = 0, .symbol = 0, .emits = false };
};

/// The code is a complete prefix code over 257 symbols, so its tree has 257
/// leaves, 256 internal nodes, and 513 nodes in total. The comptime build
/// asserts it: a tree that came out any other shape would mean the transcribed
/// table is not the code it claims to be.
const nodes_max: u16 = 513;
const node_none: u16 = std.math.maxInt(u16);

/// Every automaton state is an internal node of the tree, so there can be at
/// most 256, plus one for failure.
const states_max: u16 = 257;

const Tree = struct {
    child: [nodes_max][2]u16,
    symbol: [nodes_max]u16,
    is_leaf: [nodes_max]bool,
    /// Bits from the root, which is the padding length if input ends here.
    depth: [nodes_max]u8,
    /// Every bit from the root is a one, which is what legal padding must be.
    all_ones: [nodes_max]bool,
    count: u16,
};

fn buildTree() Tree {
    var tree: Tree = .{
        .child = [_][2]u16{[2]u16{ node_none, node_none }} ** nodes_max,
        .symbol = [_]u16{0} ** nodes_max,
        .is_leaf = [_]bool{false} ** nodes_max,
        .depth = [_]u8{0} ** nodes_max,
        .all_ones = [_]bool{false} ** nodes_max,
        .count = 1,
    };
    tree.all_ones[0] = true;

    for (table.codes, 0..) |code, symbol| {
        assert(code.bits >= table.bits_min);
        assert(code.bits <= table.bits_max);
        var node: u16 = 0;
        var index: u5 = 0;
        while (index < code.bits) : (index += 1) {
            // Descending through a leaf would mean this code has another code
            // as its prefix. Half of prefix-freeness, asserted where it would
            // happen rather than inferred from the node count afterwards.
            assert(!tree.is_leaf[node]);
            const bit: u1 = @truncate(code.code >> (code.bits - 1 - index));
            if (tree.child[node][bit] == node_none) {
                const fresh = tree.count;
                assert(fresh < nodes_max);
                tree.count += 1;
                tree.child[node][bit] = fresh;
                tree.depth[fresh] = tree.depth[node] + 1;
                tree.all_ones[fresh] = tree.all_ones[node] and bit == 1;
            }
            node = tree.child[node][bit];
        }
        // And the other half: a code cannot land on an interior node, which
        // would mean some other code is a prefix of *it*.
        assert(!tree.is_leaf[node]);
        assert(tree.child[node][0] == node_none);
        assert(tree.child[node][1] == node_none);
        tree.is_leaf[node] = true;
        tree.symbol[node] = @intCast(symbol);
    }
    assert(tree.count == nodes_max);
    return tree;
}

/// The result of walking one nibble from a state: where it lands, and the at
/// most one symbol it completes on the way.
const NibbleWalk = struct {
    node: u16,
    symbol: u8,
    emits: bool,
    failed: bool,
};

/// Walk four bits from `origin`.
///
/// At most one symbol can complete: the shortest code is five bits, so after
/// emitting, the walk restarts at the root with three bits left at most. That
/// is a comptime relation above and an assertion here.
fn walkNibble(tree: *const Tree, origin: u16, nibble: u4) NibbleWalk {
    var node = origin;
    var symbol: u8 = 0;
    var emits = false;

    var step: u3 = 0;
    while (step < 4) : (step += 1) {
        const shift: u2 = @intCast(3 - step);
        const bit: u1 = @truncate(nibble >> shift);
        node = tree.child[node][bit];
        // The tree is complete, so descent always lands somewhere.
        assert(node != node_none);
        if (tree.is_leaf[node]) {
            if (tree.symbol[node] == eos) {
                // An encoded string containing EOS is a decoding error (RFC
                // 7541 section 5.2), not a string terminator.
                return .{ .node = 0, .symbol = 0, .emits = false, .failed = true };
            }
            assert(!emits);
            emits = true;
            symbol = @intCast(tree.symbol[node]);
            node = 0;
        }
    }
    assert(step == 4);
    return .{ .node = node, .symbol = symbol, .emits = emits, .failed = false };
}

const Machine = struct {
    transitions: [states_max][16]Transition,
    accepting: [states_max]bool,
    /// Real states; the failure state sits at this index.
    count: u16,
};

fn buildMachine() Machine {
    const tree = buildTree();
    // A complete prefix code over 257 symbols, or the source table is wrong.
    assert(tree.count == nodes_max);

    var built: Machine = .{
        .transitions = [_][16]Transition{[_]Transition{Transition.blank} ** 16} ** states_max,
        .accepting = [_]bool{false} ** states_max,
        .count = 1,
    };
    var state_of_node = [_]u16{node_none} ** nodes_max;
    var node_of_state = [_]u16{0} ** states_max;
    state_of_node[0] = 0;

    var state: u16 = 0;
    while (state < built.count) : (state += 1) {
        const origin = node_of_state[state];
        for (0..16) |nibble| {
            const walk = walkNibble(&tree, origin, @intCast(nibble));
            if (walk.failed) {
                // Patched to the failure state below, once its index is known.
                built.transitions[state][nibble] = .{ .next_state = node_none, .symbol = 0, .emits = false };
                continue;
            }
            if (state_of_node[walk.node] == node_none) {
                const fresh = built.count;
                built.count += 1;
                assert(built.count <= states_max);
                state_of_node[walk.node] = fresh;
                node_of_state[fresh] = walk.node;
            }
            built.transitions[state][nibble] = .{
                .next_state = state_of_node[walk.node],
                .symbol = walk.symbol,
                .emits = walk.emits,
            };
        }
    }

    finish(&built, &tree, &node_of_state);
    return built;
}

/// Point every failed transition at the failure state, and precompute which
/// states a valid encoding may end in.
fn finish(built: *Machine, tree: *const Tree, node_of_state: *const [states_max]u16) void {
    const failure = built.count;
    assert(failure < states_max);
    for (0..failure) |index| {
        for (&built.transitions[index]) |*transition| {
            if (transition.next_state == node_none) transition.next_state = failure;
        }
        const node = node_of_state[index];
        // Section 5.2's two padding rules, precomputed: the leftover bits must
        // be the most significant bits of EOS, which are all ones, and there
        // must be fewer than eight of them.
        built.accepting[index] = tree.all_ones[node] and tree.depth[node] <= padding_bits_max;
    }
    // Absorbing, and never accepting, so failure needs no branch to detect and
    // cannot be undone by later input.
    for (&built.transitions[failure]) |*transition| {
        transition.* = .{ .next_state = failure, .symbol = 0, .emits = false };
    }
    built.accepting[failure] = false;
    assert(!built.accepting[failure]);
}

const machine = blk: {
    @setEvalBranchQuota(2_000_000);
    break :blk buildMachine();
};

/// Real automaton states, failure excluded. Pinned by a test: the count is a
/// property of the code table, and a change in it means the table changed.
pub const states_count: u16 = machine.count;

const transitions = machine.transitions;
const accepting = machine.accepting;

pub const DecodeError = error{
    /// The encoding contains EOS, ends mid-code, or pads with something other
    /// than fewer than eight one-bits.
    ///
    /// `target` may hold a partial decoding when this is returned — the failure
    /// is only detectable at the end of the input, by which time whatever was
    /// valid has already been written. Callers treat the whole string as absent
    /// rather than truncated.
    Invalid,
    /// The decoding does not fit `target`. For a header field this is the
    /// compression-bomb bound, and the caller sized it.
    OutputTooLong,
};

/// Decode `source` into `target`, returning octets written.
///
/// The loop carries no failure branch on purpose. The failure state absorbs and
/// emits nothing, so a malformed input stops producing output at the point it
/// goes wrong and is caught by the accepting check at the end. That leaves the
/// bound on wasted work as `source.len`, which the caller has already bounded,
/// and keeps the hot path to two lookups and two predictable branches per
/// octet.
pub fn decode(target: []u8, source: []const u8) DecodeError!u32 {
    // `written` is a u32, which is a precondition rather than an assumption.
    assert(target.len <= std.math.maxInt(u32));
    var state: u16 = 0;
    var written: u32 = 0;

    for (source) |octet| {
        // Narrowed so the row index is a type property rather than a bounds
        // check the optimizer has to rediscover, in the one loop this file's
        // whole design argument is about.
        const high = transitions[state][@as(u4, @truncate(octet >> 4))];
        if (high.emits) {
            if (written == target.len) return error.OutputTooLong;
            target[written] = high.symbol;
            written += 1;
        }
        state = high.next_state;

        const low = transitions[state][@as(u4, @truncate(octet))];
        if (low.emits) {
            if (written == target.len) return error.OutputTooLong;
            target[written] = low.symbol;
            written += 1;
        }
        state = low.next_state;
    }

    assert(state < states_max);
    if (!accepting[state]) return error.Invalid;
    return written;
}

/// Octets `encode` would write for `source`.
pub fn encodedLength(source: []const u8) u64 {
    var bits: u64 = 0;
    for (source) |octet| bits += table.codes[octet].bits;
    assert(bits >= @as(u64, source.len) * bits_min);
    return std.math.divCeil(u64, bits, 8) catch unreachable;
}

pub const EncodeError = error{
    OutputTooLong,
};

/// Encode `source` into `target`, returning octets written.
pub fn encode(target: []u8, source: []const u8) EncodeError!u32 {
    if (encodedLength(source) > target.len) return error.OutputTooLong;

    // Holding fewer than eight bits before each symbol and adding at most
    // thirty keeps the accumulator under thirty-eight bits, so it never
    // overflows and the flush never has to check.
    const length = encodedLength(source);
    var accumulator: u64 = 0;
    var bits: u6 = 0;
    var written: u32 = 0;

    for (source) |octet| {
        const code = table.codes[octet];
        assert(bits < 8);
        accumulator = (accumulator << code.bits) | code.code;
        bits += code.bits;
        // Seven carried in plus the longest code. Asserting the proof rather
        // than a round number above it.
        assert(bits <= 7 + @as(u6, bits_max));
        while (bits >= 8) {
            bits -= 8;
            // The up-front length check is all that stands between a
            // length/emit disagreement and a write past the end, so the
            // negative space belongs here rather than only in the postcondition
            // that would notice afterwards.
            assert(written < length);
            target[written] = @truncate(accumulator >> bits);
            written += 1;
        }
    }

    if (bits > 0) {
        assert(bits < 8);
        const padding: u6 = 8 - bits;
        // Pad with the most significant bits of EOS, which are ones.
        const ones: u64 = (@as(u64, 1) << padding) - 1;
        assert(written < length);
        target[written] = @truncate((accumulator << padding) | ones);
        written += 1;
    }

    assert(written == length);
    return written;
}

test "the automaton has the state count the construction predicts" {
    // 256 internal nodes in a 257-leaf tree, every one of them reachable at a
    // nibble boundary. nghttp2's table is the same size, from the same
    // construction.
    try std.testing.expectEqual(@as(u16, 256), states_count);
}

test "RFC 7541 Appendix C: every Huffman string, both directions" {
    var decoded: [128]u8 = undefined;
    var encoded: [128]u8 = undefined;
    for (@import("rfc7541_examples.zig").huffman_strings) |vector| {
        const written = try decode(&decoded, vector.wire);
        try std.testing.expectEqualStrings(vector.text, decoded[0..written]);

        // The RFC's bytes are what a conforming encoder produces, so this is a
        // real check on ours rather than a round trip against itself.
        const length = try encode(&encoded, vector.text);
        try std.testing.expectEqualSlices(u8, vector.wire, encoded[0..length]);
    }
}

test "every octet round trips, alone and in a full-alphabet run" {
    var source: [256]u8 = undefined;
    for (&source, 0..) |*octet, index| octet.* = @intCast(index);

    var encoded: [2048]u8 = undefined;
    var decoded: [512]u8 = undefined;

    // The whole alphabet at once, including the 30-bit codes.
    const length = try encode(&encoded, &source);
    const written = try decode(&decoded, encoded[0..length]);
    try std.testing.expectEqualSlices(u8, &source, decoded[0..written]);

    // And each octet on its own, where padding is the whole tail.
    for (source) |octet| {
        const one = [_]u8{octet};
        const encoded_len = try encode(&encoded, &one);
        const decoded_len = try decode(&decoded, encoded[0..encoded_len]);
        try std.testing.expectEqualSlices(u8, &one, decoded[0..decoded_len]);
    }
}

test "an empty string encodes and decodes to nothing" {
    var target: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), try encode(&target, ""));
    try std.testing.expectEqual(@as(u64, 0), encodedLength(""));
    try std.testing.expectEqual(@as(u32, 0), try decode(&target, ""));
}

test "padding longer than seven bits is rejected" {
    // "0" is the 5-bit code 00000. One octet of it pads with three ones and is
    // valid; a second all-ones octet is eight bits of padding and is not.
    var target: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), try decode(&target, &.{0b0000_0111}));
    try std.testing.expectError(error.Invalid, decode(&target, &.{ 0b0000_0111, 0xff }));
}

test "padding that is not all ones is rejected" {
    // Same 5-bit "0", padded with 000 instead of 111.
    var target: [8]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(&target, &.{0b0000_0000}));
}

test "an encoded EOS is a decoding error" {
    // EOS is thirty one-bits. Four all-ones octets reach it and then some.
    var target: [16]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(&target, &.{ 0xff, 0xff, 0xff, 0xff }));
}

test "a truncated code is rejected rather than silently dropped" {
    // The first octet of "www.example.com" alone ends mid-code.
    var target: [64]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(&target, &.{0xae}));
}

test "decode stops at the target's capacity" {
    var target: [4]u8 = undefined;
    const wire = [_]u8{ 0xae, 0xc3, 0x77, 0x1a, 0x4b }; // 15 octets of output
    try std.testing.expectError(error.OutputTooLong, decode(&target, &wire));
}

test "encode refuses a target that cannot hold the result" {
    var target: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooLong, encode(&target, "www.example.com"));
}
