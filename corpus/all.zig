//! Root of the corpus test binary, which carries two unrelated vendored
//! corpora: HPACK encodings from other implementations, and HTTP/2 frame
//! fixtures. Both need an allocator and a JSON parser, and neither belongs in
//! a package that promises no allocator and ships no fixtures.

test {
    _ = @import("hpack.zig");
    _ = @import("frames.zig");
}
