const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The public module: consumers `@import("h2")` this.
    const h2_module = b.addModule("h2", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "h2",
        .root_module = h2_module,
    });
    b.installArtifact(lib);

    const module_tests = b.addRunArtifact(b.addTest(.{ .root_module = h2_module }));

    // The boundary lint of docs/TIGER_STYLE.md. Its own tests ride the `test`
    // step: a lint whose rules are untested is a lint that silently stops
    // having rules.
    const lint_exe = b.addExecutable(.{
        .name = "h2-lint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/lint.zig"),
            .target = b.graph.host,
        }),
    });
    const lint_tests = b.addRunArtifact(b.addTest(.{ .root_module = lint_exe.root_module }));

    const lint_run = b.addRunArtifact(lint_exe);
    lint_run.addDirectoryArg(b.path("src"));
    const lint_step = b.step("lint", "Boundary lint: no I/O types, no allocator, no unbounded loops");
    lint_step.dependOn(&lint_run.step);

    // The fuzz gate. `zig build fuzz` replays the corpus as regression; with
    // `--fuzz` it runs coverage-guided. See fuzz/fuzz.zig for why the harness
    // lives outside `src/`.
    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("fuzz/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "h2", .module = h2_module },
        },
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_module,
        // Patched copy of the default test runner; the stock one fails to
        // compile in fuzz mode (`-ffuzz`) on Zig 0.16.0. See the doc comment
        // in the file. Vendored from zoxy-io/hparse, and deletable together
        // with this override once upstream ships the fix.
        .test_runner = .{ .path = b.path("fuzz/test_runner.zig"), .mode = .server },
        // The self-hosted x86_64 backend emits no fuzz coverage
        // instrumentation: the build runner's coverage thread panics on an
        // empty PC table.
        .use_llvm = true,
    });
    const fuzz_run = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run the fuzz harness (pass --fuzz to actually fuzz)");
    fuzz_step.dependOn(&fuzz_run.step);

    // The performance gate. ReleaseFast is hardcoded rather than offered:
    // `standardOptimizeOption`'s `preferred_optimize_mode` still yields Debug
    // unless `-Drelease` is passed, and a benchmark built in Debug reports
    // numbers that mean nothing. See bench/main.zig for the other footgun.
    const bench_runs = b.option(u64, "runs", "Repetitions per workload (default 5)") orelse 5;
    const bench_iterations = b.option(u64, "iterations", "Units of work per run (default 1_000_000)") orelse 1_000_000;
    const bench_options = b.addOptions();
    bench_options.addOption(u64, "runs", bench_runs);
    bench_options.addOption(u64, "iterations", bench_iterations);

    const bench_exe = b.addExecutable(.{
        .name = "h2-bench",
        // Zig 0.16's self-hosted x86_64 backend scalarizes `@Vector` code, and
        // HPACK's Huffman decode is exactly the kind of work that would
        // silently lose an order of magnitude without this.
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "h2", .module = h2_module },
                .{ .name = "bench_options", .module = bench_options.createModule() },
            },
        }),
    });
    const bench_run = b.addRunArtifact(bench_exe);
    if (b.args) |args| bench_run.addArgs(args);
    const bench_step = b.step("bench", "Run the decode/encode microbenchmarks (ReleaseFast)");
    bench_step.dependOn(&bench_run.step);

    const test_step = b.step("test", "Run unit tests, the lint's own tests, and the fuzz corpus");
    test_step.dependOn(&module_tests.step);
    test_step.dependOn(&lint_tests.step);
    // A corpus replayed only under `zig build fuzz` is a corpus that rots.
    test_step.dependOn(&fuzz_run.step);

    // Every per-change gate behind one name, so CI and a local check cannot
    // drift apart. `bench` is deliberately excluded: its verdict is a band
    // comparison a human makes across runs, not a pass/fail a shared runner
    // can produce. CLAUDE.md requires it by hand for a change that touches a
    // decode or encode path.
    const ci_step = b.step("ci", "Per-change gates: test + lint (bench is run by hand)");
    ci_step.dependOn(test_step);
    ci_step.dependOn(lint_step);
}
