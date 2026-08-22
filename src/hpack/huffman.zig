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

/// One nibble's transition. Four octets, so a row is 64 and the whole table is
/// `states_count` times that.
const Transition = struct {
    next: u16,
    symbol: u8,
    emits: bool,

    /// A transition that goes nowhere and emits nothing, used to fill the
    /// table before the walk overwrites it.
    const blank: Transition = .{ .next = 0, .symbol = 0, .emits = false };
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
        var node: u16 = 0;
        var index: u5 = 0;
        while (index < code.bits) : (index += 1) {
            const bit: u1 = @truncate(code.code >> (code.bits - 1 - index));
            if (tree.child[node][bit] == node_none) {
                const fresh = tree.count;
                tree.count += 1;
                tree.child[node][bit] = fresh;
                tree.depth[fresh] = tree.depth[node] + 1;
                tree.all_ones[fresh] = tree.all_ones[node] and bit == 1;
            }
            node = tree.child[node][bit];
        }
        tree.is_leaf[node] = true;
        tree.symbol[node] = @intCast(symbol);
    }
    return tree;
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
            var node = origin;
            var symbol: u8 = 0;
            var emits = false;
            var failed = false;

            var step: u2 = 0;
            while (true) : (step += 1) {
                assert(step < 4);
                const bit: u1 = @truncate(nibble >> (3 - step));
                node = tree.child[node][bit];
                // The tree is complete, so descent always lands somewhere.
                assert(node != node_none);
                if (tree.is_leaf[node]) {
                    if (tree.symbol[node] == eos) {
                        // An encoded string containing EOS is a decoding error
                        // (RFC 7541 section 5.2), not a string terminator.
                        failed = true;
                        break;
                    }
                    // Four bits cannot finish two codes: the shortest is five,
                    // so after emitting we restart at the root with at most
                    // three bits left.
                    assert(!emits);
                    emits = true;
                    symbol = @intCast(tree.symbol[node]);
                    node = 0;
                }
                if (step == 3) break;
            }

            if (failed) {
                // Patched to the failure state below, once its index is known.
                built.transitions[state][nibble] = .{ .next = node_none, .symbol = 0, .emits = false };
                continue;
            }
            if (state_of_node[node] == node_none) {
                const fresh = built.count;
                built.count += 1;
                assert(built.count <= states_max);
                state_of_node[node] = fresh;
                node_of_state[fresh] = node;
            }
            built.transitions[state][nibble] = .{
                .next = state_of_node[node],
                .symbol = symbol,
                .emits = emits,
            };
        }
    }

    const failure = built.count;
    assert(failure < states_max);
    for (0..failure) |index| {
        for (&built.transitions[index]) |*transition| {
            if (transition.next == node_none) transition.next = failure;
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
        transition.* = .{ .next = failure, .symbol = 0, .emits = false };
    }
    built.accepting[failure] = false;
    return built;
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
    var state: u16 = 0;
    var written: u32 = 0;

    for (source) |octet| {
        const high = transitions[state][octet >> 4];
        if (high.emits) {
            if (written == target.len) return error.OutputTooLong;
            target[written] = high.symbol;
            written += 1;
        }
        state = high.next;

        const low = transitions[state][octet & 0x0f];
        if (low.emits) {
            if (written == target.len) return error.OutputTooLong;
            target[written] = low.symbol;
            written += 1;
        }
        state = low.next;
    }

    assert(state < states_max);
    if (!accepting[state]) return error.Invalid;
    assert(written <= target.len);
    return written;
}

/// Octets `encode` would write for `source`.
pub fn encodedLength(source: []const u8) u64 {
    var bits: u64 = 0;
    for (source) |octet| bits += table.codes[octet].bits;
    assert(bits <= @as(u64, source.len) * bits_max);
    return (bits + 7) / 8;
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
    var accumulator: u64 = 0;
    var bits: u6 = 0;
    var written: u32 = 0;

    for (source) |octet| {
        const code = table.codes[octet];
        assert(bits < 8);
        accumulator = (accumulator << code.bits) | code.code;
        bits += code.bits;
        assert(bits <= 38); // 7 carried in, plus the longest code.
        while (bits >= 8) {
            bits -= 8;
            target[written] = @truncate(accumulator >> bits);
            written += 1;
        }
    }

    if (bits > 0) {
        assert(bits < 8);
        const padding: u6 = 8 - bits;
        // Pad with the most significant bits of EOS, which are ones.
        const ones: u64 = (@as(u64, 1) << padding) - 1;
        target[written] = @truncate((accumulator << padding) | ones);
        written += 1;
    }

    assert(written == encodedLength(source));
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
