//! Microbenchmarks for the decode and encode paths, run as `zig build bench`.
//!
//! In-process rather than hparse's subprocess-per-implementation shape: there
//! is nothing to compare against yet. When there is — nghttp2's HPACK is the
//! obvious first — it arrives as hparse does it, a C binary under `bench/`
//! compiled by Zig's bundled clang, outside `src/` and outside the lint's
//! walk. The reporting table below is already the shape that comparison wants.
//!
//! Two footguns this harness exists to have gotten right once, both learned in
//! hparse:
//!
//! 1. **ReleaseFast is hardcoded**, not offered. `standardOptimizeOption`'s
//!    `preferred_optimize_mode` does *not* do this — it still yields Debug
//!    unless `-Drelease` is passed, which produces numbers that mean nothing.
//! 2. **`use_llvm` is set** in build.zig. Zig 0.16's self-hosted x86_64 backend
//!    scalarizes `@Vector` code, and HPACK's Huffman decode is exactly the kind
//!    of table-and-vector work that would silently lose an order of magnitude.
//!
//! Read the numbers as bands across runs, never as single values. `min` is the
//! least noisy signal on a laptop; `mean` and `max` say how much the machine
//! was interfering while it was collected.

const std = @import("std");
const bench_options = @import("bench_options");

const h2 = @import("h2");

const assert = std.debug.assert;

const hpack = h2.hpack;
const examples = hpack.rfc7541_examples;

/// The four RFC 7541 Appendix C stories are the workload rather than a
/// synthetic string, for the reason hparse benchmarks against real requests:
/// Huffman throughput depends entirely on the code-length distribution of the
/// input, and header text is nothing like uniform bytes. All 98 symbols with
/// codes of 15 bits or fewer are printable ASCII, and ten of the shortest five
/// are `0 1 2 a c e i o s t`.
const stories = examples.stories;

/// A realistic single value, for the kernel-only workloads: a date header, 29
/// octets of text in 22 of wire.
const date_text = "Mon, 21 Oct 2013 20:13:21 GMT";

/// Workloads are registered here and nowhere else, so adding one is a row
/// rather than a new file with its own timing loop to get subtly wrong.
const workloads = [_]Workload{
    .{ .name = "frame header", .run = benchFrameHeader },
    .{ .name = "frame parse", .run = benchFrameParse },
    .{ .name = "frame render", .run = benchFrameRender },
    .{ .name = "hpack decode", .run = benchHpackDecode },
    .{ .name = "hpack encode", .run = benchHpackEncode },
    .{ .name = "hpack encode static", .run = benchHpackEncodeStatic },
    .{ .name = "huffman decode", .run = benchHuffmanDecode },
    .{ .name = "huffman decode ref", .run = benchHuffmanDecodeReference },
    .{ .name = "huffman decode long", .run = benchHuffmanDecodeLong },
    .{ .name = "huffman decode long ref", .run = benchHuffmanDecodeLongReference },
    .{ .name = "huffman encode", .run = benchHuffmanEncode },
};

const Workload = struct {
    name: []const u8,
    /// Runs `iterations` units of work and returns a value derived from all
    /// of them.
    ///
    /// Returning it is not enough on its own: a workload must also call
    /// `doNotOptimizeAway` on each unit's result *inside* the loop. The
    /// placeholder this harness shipped with was written without that, and
    /// ReleaseFast folded the whole loop to a constant and reported 0.000s —
    /// which is what the harness exists to not do quietly. A real decode has a
    /// live output the optimizer cannot fold, but it can still hoist an
    /// invariant parse out of the loop, so the barrier stays.
    run: *const fn (iterations: u64) u64,
};

const Result = struct {
    name: []const u8,
    min_ns: u64,
    mean_ns: u64,
    max_ns: u64,
};

/// Parse, validate and render every frame header in the vendored fixtures.
///
/// Nine octets of shifts is not where a proxy spends its time, and this number
/// is not here to be optimized. It is here as the baseline the payload codec
/// will be measured against: when parsing a frame stops being a header read and
/// starts being a header read plus a payload walk, the difference is the thing
/// worth knowing, and it cannot be recovered afterwards.
fn benchFrameHeader(iterations: u64) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        for (frame_headers) |wire| {
            const header = h2.frame.Header.parse(&wire) catch unreachable;
            // The verdict is consumed, not discarded. A `catch {}` here left
            // the validation dead and the optimizer free to drop most of it —
            // which is the exact failure the `Workload` doc warns about, and it
            // read as a three-times-faster header parse than the real one.
            const verdict: u64 = if (header.validate(h2.frame.Header.max_frame_size_min))
                0
            else |err|
                @intFromEnum(h2.frame.Header.errorCode(err));
            var rendered: [h2.frame.Header.octets]u8 = undefined;
            _ = h2.frame.Header.render(header, &rendered) catch unreachable;
            checksum +%= header.length +% rendered[0] +% verdict;
            std.mem.doNotOptimizeAway(checksum);
        }
    }
    return checksum;
}

/// Header and payload together, over whole frames.
///
/// The header workload above is the baseline this is read against: the
/// difference between the two is what walking a payload costs, and it is the
/// number a later change to either layer has to be compared with.
fn benchFrameParse(iterations: u64) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        for (frames) |wire| {
            const header = h2.frame.Header.parse(wire) catch unreachable;
            header.validate(h2.frame.Header.max_frame_size_min) catch continue;
            const body = wire[h2.frame.Header.octets..][0..header.length];
            const payload = h2.frame.payload.parse(header, body) catch continue;
            checksum +%= switch (payload) {
                .data => |data| data.data.len,
                .headers => |headers| headers.fragment.len,
                .priority => |priority| priority.weight(),
                .rst_stream => |rst| @intFromEnum(rst.error_code),
                .settings => |settings| settings.count(),
                .push_promise => |promise| promise.promised_stream_identifier,
                .ping => |ping| ping.opaque_data[0],
                .goaway => |goaway| goaway.debug_data.len,
                .window_update => |update| update.increment,
                .continuation => |continuation| continuation.fragment.len,
                .unknown => |octets| octets.len,
            };
            std.mem.doNotOptimizeAway(checksum);
        }
    }
    return checksum;
}

/// Parse and render each frame, which is what forwarding one costs.
///
/// The parse is inside the loop on purpose: a payload borrows from the octets
/// it was read from, so hoisting it would measure rendering against buffers a
/// real forwarder does not keep. Read this as a delta against `frame parse`
/// rather than as a rendering figure on its own.
fn benchFrameRender(iterations: u64) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        for (frames) |wire| {
            const header = h2.frame.Header.parse(wire) catch unreachable;
            header.validate(h2.frame.Header.max_frame_size_min) catch continue;
            const body = wire[h2.frame.Header.octets..][0..header.length];
            const payload = h2.frame.payload.parse(header, body) catch continue;
            // Not a workaround: `render` refuses an unknown type, and this
            // measures forwarding frames that can be forwarded.
            if (payload == .unknown) continue;

            var target: [256]u8 = undefined;
            const sender_flags = header.flags & ~h2.frame.payload.structuralFlags(&payload);
            const written = h2.frame.payload.render(
                &payload,
                header.stream_identifier,
                sender_flags,
                &target,
            ) catch continue;
            checksum +%= written +% target[0];
            std.mem.doNotOptimizeAway(checksum);
        }
    }
    return checksum;
}

/// Whole frames, header and payload, of the shapes a connection carries.
///
/// Written as string literals rather than octet arrays because most of a real
/// frame is text — a field block fragment, a debug message — and escaping the
/// nine binary octets reads better than spelling out thirteen printable ones.
const frames = [_][]const u8{
    // SETTINGS with two parameters.
    "\x00\x00\x0c\x04\x00\x00\x00\x00\x00" ++
        "\x00\x01\x00\x00\x20\x00" ++ "\x00\x03\x00\x00\x13\x88",
    // SETTINGS ack.
    "\x00\x00\x00\x04\x01\x00\x00\x00\x00",
    // HEADERS carrying a field block fragment.
    "\x00\x00\x0d\x01\x04\x00\x00\x00\x01" ++ "this is dummy",
    // HEADERS, padded and prioritized.
    "\x00\x00\x17\x01\x2c\x00\x00\x00\x03" ++
        "\x04" ++ "\x80\x00\x00\x14\x09" ++ "this is dummy" ++ "\x00\x00\x00\x00",
    // DATA, padded.
    "\x00\x00\x14\x00\x08\x00\x00\x00\x02" ++ "\x06" ++ "Hello, world!" ++ "Howdy!",
    // PRIORITY.
    "\x00\x00\x05\x02\x00\x00\x00\x00\x09" ++ "\x00\x00\x00\x0b\x07",
    // RST_STREAM.
    "\x00\x00\x04\x03\x00\x00\x00\x00\x05" ++ "\x00\x00\x00\x08",
    // PING.
    "\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "deadbeef",
    // GOAWAY with debug data.
    "\x00\x00\x17\x07\x00\x00\x00\x00\x00" ++
        "\x00\x00\x00\x1e\x00\x00\x00\x09" ++ "hpack is broken",
    // WINDOW_UPDATE.
    "\x00\x00\x04\x08\x00\x00\x00\x00\x32" ++ "\x00\x00\x03\xe8",
    // CONTINUATION.
    "\x00\x00\x0d\x09\x00\x00\x00\x00\x32" ++ "this is dummy",
    // An unknown type, skipped by its length.
    "\x00\x00\x03\xfa\xff\x00\x00\x00\x07" ++ "\x01\x02\x03",
    // And two that fail, so the error paths are in the mix a connection sees
    // rather than measured only on frames that succeed.
    "\x00\x00\x04\x08\x00\x00\x00\x00\x05" ++ "\x00\x00\x00\x00",
    "\x00\x00\x04\x00\x08\x00\x00\x00\x01" ++ "\x04\x00\x00\x00",
};

/// The first nine octets of a spread of real frames: every type, valid and
/// malformed, so branch prediction sees the same mix a connection does rather
/// than one shape repeated.
const frame_headers = [_][h2.frame.Header.octets]u8{
    .{ 0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, // SETTINGS
    .{ 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 }, // SETTINGS ack
    .{ 0x00, 0x00, 0x14, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01 }, // HEADERS
    .{ 0x00, 0x00, 0x23, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x03 }, // HEADERS, padded and prioritized
    .{ 0x00, 0x00, 0x14, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02 }, // DATA, padded
    .{ 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x09 }, // PRIORITY
    .{ 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x05 }, // RST_STREAM
    .{ 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 }, // PING
    .{ 0x00, 0x00, 0x17, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }, // GOAWAY
    .{ 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x32 }, // WINDOW_UPDATE
    .{ 0x00, 0x00, 0x0d, 0x09, 0x00, 0x00, 0x00, 0x00, 0x32 }, // CONTINUATION
    .{ 0x00, 0x00, 0x04, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }, // GOAWAY, too short
    .{ 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x09 }, // PRIORITY, wrong length
    .{ 0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03 }, // SETTINGS on a stream
    .{ 0x00, 0x00, 0x10, 0xfa, 0xff, 0x00, 0x00, 0x00, 0x07 }, // an unknown type
};

/// Decode every Appendix C header block, each story against a fresh
/// compression context so evictions happen where the RFC says they do.
///
/// This is zoxy's hot path: a proxy decodes one request block per stream and
/// wants the fields, so the measurement includes resolving indices and copying
/// out of the dynamic table, not just the Huffman kernel.
fn benchHpackDecode(iterations: u64) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        for (stories) |story| {
            var storage: hpack.DynamicTable.Storage(4096) = .{};
            var decoder = hpack.Decoder.init(storage.table(), 64 * 1024);
            for (story.examples) |example| {
                var buffer: [4096]u8 = undefined;
                var iterator = decoder.iterate(&buffer, example.wire);
                while (iterator.next() catch null) |field| {
                    // Consumed, so the decode cannot be folded away. A field
                    // the optimizer can prove is unread is a field it can
                    // decline to produce.
                    checksum +%= field.name.len +% field.value.len;
                    std.mem.doNotOptimizeAway(checksum);
                }
            }
        }
    }
    return checksum;
}

/// Encode every Appendix C header list, each story against a fresh context.
///
/// This is zoxy's response path, and the cost centre is lookup rather than
/// Huffman: a static-table probe and, on a miss, a scan of the dynamic table's
/// hashes.
fn benchHpackEncode(iterations: u64) u64 {
    return benchEncode(iterations, .dynamic);
}

/// The same lists in static-only mode, which is zrk's path.
///
/// zrk encodes once at startup and replays, so this number is not on its hot
/// path at all. It is here as the other half of the comparison: the difference
/// between the two is what the dynamic table's bookkeeping costs.
fn benchHpackEncodeStatic(iterations: u64) u64 {
    return benchEncode(iterations, .static_only);
}

/// The body of both, which differ only in mode. Kept in one place so the two
/// numbers stay comparable: a change to one that missed the other would look
/// like a result.
fn benchEncode(iterations: u64, mode: hpack.Encoder.Mode) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        for (stories) |story| {
            var storage: hpack.Encoder.Storage(4096) = .{};
            var encoder = storage.encoder(mode);
            for (story.examples) |example| {
                var block: [4096]u8 = undefined;
                const encoded = encoder.encode(&block, example.fields);
                assert(encoded.fields == example.fields.len);
                checksum +%= encoded.written;
                std.mem.doNotOptimizeAway(checksum);
            }
        }
    }
    return checksum;
}

/// The Huffman kernel on its own, where a change to it shows up undiluted by
/// the representation layer above.
fn benchHuffmanDecode(iterations: u64) u64 {
    return benchDecodeKernel(iterations, date_wire, .window);
}

/// The date header's wire form, lifted from the RFC's own vectors.
const date_wire = blk: {
    for (examples.huffman_strings) |vector| {
        if (std.mem.eql(u8, vector.text, date_text)) break :blk vector.wire;
    }
    unreachable;
};

/// A long, realistic value: one set-cookie of the shape the RFC's own C.5.3
/// uses, extended with the attributes a real one carries — 132 octets of text.
const long_text = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1; " ++
    "path=/some/reasonably/long/path; domain=www.example.com; secure; httponly";

const long_wire = blk: {
    @setEvalBranchQuota(200_000);
    var buffer: [512]u8 = undefined;
    const length = hpack.huffman.encode(&buffer, long_text) catch unreachable;
    break :blk buffer[0..length].*;
};

/// The retired nibble automaton on the same value, so the two numbers are a
/// direct comparison on identical input.
fn benchHuffmanDecodeReference(iterations: u64) u64 {
    return benchDecodeKernel(iterations, date_wire, .automaton);
}

/// A longer value, where the per-call cost stops dominating.
///
/// A header value of twenty-nine octets is realistic and also short enough that
/// setting up a bit reader is a visible fraction of the work. A cookie or a
/// long location header is where a wider window is supposed to pay, so both
/// lengths are measured rather than one.
fn benchHuffmanDecodeLong(iterations: u64) u64 {
    return benchDecodeKernel(iterations, &long_wire, .window);
}

fn benchHuffmanDecodeLongReference(iterations: u64) u64 {
    return benchDecodeKernel(iterations, &long_wire, .automaton);
}

const Kernel = enum { window, automaton };

fn benchDecodeKernel(iterations: u64, wire: []const u8, kernel: Kernel) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        var decoded: [1024]u8 = undefined;
        const written = switch (kernel) {
            .window => hpack.huffman.decode(&decoded, wire) catch unreachable,
            .automaton => hpack.huffman.decodeReference(&decoded, wire) catch unreachable,
        };
        assert(written >= 1);
        checksum +%= written +% decoded[0];
        std.mem.doNotOptimizeAway(checksum);
    }
    return checksum;
}

fn benchHuffmanEncode(iterations: u64) u64 {
    assert(iterations >= 1);
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        var wire: [64]u8 = undefined;
        const written = hpack.huffman.encode(&wire, date_text) catch unreachable;
        checksum +%= written;
        std.mem.doNotOptimizeAway(checksum);
    }
    return checksum;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const runs: u64 = bench_options.runs;
    const iterations: u64 = bench_options.iterations;
    assert(runs >= 1);
    assert(iterations >= 1);

    var results: [workloads.len]Result = undefined;
    for (&results, workloads) |*result, workload| {
        result.* = measure(io, workload, runs, iterations);
    }

    report(&results, iterations);
}

/// Times `runs` repetitions of one workload and reduces them to a band.
fn measure(io: std.Io, workload: Workload, runs: u64, iterations: u64) Result {
    assert(runs >= 1);
    assert(iterations >= 1);

    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;
    var total_ns: u128 = 0;

    var run: u64 = 0;
    while (run < runs) : (run += 1) {
        const started = std.Io.Clock.awake.now(io).nanoseconds;
        const produced = workload.run(iterations);
        const finished = std.Io.Clock.awake.now(io).nanoseconds;
        std.mem.doNotOptimizeAway(produced);
        assert(finished >= started);

        const elapsed_ns: u64 = @intCast(finished - started);
        min_ns = @min(min_ns, elapsed_ns);
        max_ns = @max(max_ns, elapsed_ns);
        total_ns += elapsed_ns;
    }
    assert(run == runs);
    assert(min_ns <= max_ns);

    return .{
        .name = workload.name,
        .min_ns = min_ns,
        .mean_ns = @intCast(total_ns / runs),
        .max_ns = max_ns,
    };
}

fn report(results: []const Result, iterations: u64) void {
    assert(results.len >= 1);
    assert(iterations >= 1);

    std.debug.print("\n{s:<24} {s:>12} {s:>12} {s:>12} {s:>12}\n", .{
        "workload", "min", "mean", "max", "ns/op",
    });
    std.debug.print("{s}\n", .{"-" ** 77});
    for (results) |result| {
        assert(result.min_ns <= result.max_ns);
        std.debug.print("{s:<24} {d:>11.3}s {d:>11.3}s {d:>11.3}s {d:>12.3}\n", .{
            result.name,
            seconds(result.min_ns),
            seconds(result.mean_ns),
            seconds(result.max_ns),
            nanosecondsPerOp(result.min_ns, iterations),
        });
    }
    std.debug.print(
        "\n{d} iterations per run. Compare bands across runs, never single numbers.\n",
        .{iterations},
    );
}

fn seconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_s;
}

/// Reported off `min`, which is the least noise-contaminated of the three.
fn nanosecondsPerOp(min_ns: u64, iterations: u64) f64 {
    assert(iterations >= 1);
    return @as(f64, @floatFromInt(min_ns)) / @as(f64, @floatFromInt(iterations));
}
