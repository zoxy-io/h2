//! Root of the corpus test binary: vendored HTTP/2 frame fixtures. They need an
//! allocator and a JSON parser, and neither belongs in a package that promises
//! no allocator and ships no fixtures.
//!
//! The HPACK interoperability corpus that used to sit beside this one went with
//! HPACK to zoxy-io/hpack, where `zig build corpus` still runs it.

test {
    _ = @import("frames.zig");
}
