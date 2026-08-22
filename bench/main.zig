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
    .{ .name = "hpack decode", .run = benchHpackDecode },
    .{ .name = "huffman decode", .run = benchHuffmanDecode },
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

/// The nibble automaton on its own, where a change to the table shows up
/// undiluted by the representation layer above it.
fn benchHuffmanDecode(iterations: u64) u64 {
    assert(iterations >= 1);
    const wire = comptime blk: {
        for (examples.huffman_strings) |vector| {
            if (std.mem.eql(u8, vector.text, date_text)) break :blk vector.wire;
        }
        unreachable;
    };
    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        var decoded: [64]u8 = undefined;
        const written = hpack.huffman.decode(&decoded, wire) catch unreachable;
        checksum +%= written;
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
