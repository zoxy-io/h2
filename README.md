# h2

![GitHub License](https://img.shields.io/github/license/zoxy-io/h2?color=orange)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-x86_64-linux.yml?label=x86_64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-aarch64-linux.yml?label=aarch64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-x86_64-windows.yml?label=x86_64-windows)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-macos.yml?label=macos)

HTTP/2 frame codec and message validation for Zig 0.16.

h2 parses and renders the ten HTTP/2 frame types, reassembles field blocks
split across CONTINUATION frames, and checks that a decoded field section is
a well-formed request or response under RFC 9113 §8. HPACK is provided by
[hpack](https://github.com/zoxy-io/hpack) and re-exported as `h2.hpack`.

It is a codec, not a connection. Stream state, flow control, SETTINGS
negotiation, sockets and TLS are the caller's. The library never allocates,
never copies where a slice will do, and never reads from a socket: bytes in,
frames and fields out.

## What is implemented

| Area | Coverage |
|---|---|
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) §4–§6 frames | The nine-octet header, all ten frame types with padding and priority fields, SETTINGS as an iterator over entries, render and parse in both directions |
| RFC 9113 §7 errors | Every parse or validation error maps to an RFC error code and a severity, so the caller knows whether to reset the stream or close the connection |
| RFC 9113 §6.2, §6.10 CONTINUATION | `BlockAssembler` joins a field block across frames into a caller-owned buffer whose length bounds the block. It rejects interleaved frames and caps the frame count |
| RFC 9113 §8.2, §8.3 messages | Field name and value octet rules, pseudo-header ordering, presence and uniqueness, connection-specific fields, `TE`, CONNECT, and RFC 9110 `content-length` syntax and agreement. Requests, responses and trailers |
| [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) HPACK | Via `h2.hpack`: encoder, decoder, dynamic table, Huffman coding |

Every frame type is checked against the
[http2jp/http2-frame-test-case](https://github.com/http2jp/http2-frame-test-case)
fixtures vendored under `corpus/`, including the 22 error cases.

## Installation

```sh
zig fetch --save git+https://github.com/zoxy-io/h2
```

```zig
// build.zig
const h2 = b.dependency("h2", .{
    .target = target,
    .optimize = optimize,
    // Optional. Assertions are on in every optimize mode unless disabled here.
    // .assertions = false,
});
exe.root_module.addImport("h2", h2.module("h2"));
```

h2 depends on [hpack](https://github.com/zoxy-io/hpack) and nothing else.

## Usage

Receiving: parse the header, slice the payload, feed it to the assembler,
and decode the completed block one field at a time through HPACK and the
message validator.

```zig
const h2 = @import("h2");

var assembler: h2.frame.BlockAssembler = .init(&block_buffer, h2.frame.BlockAssembler.frames_max_default);
var decoder: h2.hpack.Decoder = .init(hpack_storage.table(), list_size_max);

var offset: usize = 0;
while (offset < wire.len) {
    const header = try h2.frame.Header.parse(wire[offset..]);
    try header.validate(max_frame_size);
    offset += h2.frame.Header.octets;

    const body = wire[offset..][0..header.length];
    offset += header.length;
    const payload = try h2.frame.payload.parse(header, body);

    const block = switch (try assembler.accept(header, &payload)) {
        .passthrough, .fragment => continue, // a non-HEADERS frame, or more to come
        .block => |complete| complete,
    };

    var validator: h2.fields.MessageValidator = .init(.{ .kind = .request, .rules = .strict });
    var iterator = decoder.iterate(&field_buffer, block.fragment);
    while (try iterator.next()) |field| {
        try validator.field(&field);
        // field.name, field.value borrow from field_buffer until the next call
    }
    try validator.finish();
}
```

Sending: encode the fields with HPACK, then render a frame header in front
of each fragment.

```zig
var storage: h2.hpack.Encoder.Storage(4096) = .{};
var encoder = storage.encoder(.dynamic);

var block: [256]u8 = undefined;
const encoded = encoder.encode(&block, &.{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = ":path", .value = "/" },
});

const header: h2.frame.Header = .{
    .length = @intCast(encoded.written),
    .frame_type = .headers,
    .flags = h2.frame.Flag.end_headers.bit() | h2.frame.Flag.end_stream.bit(),
    .stream_identifier = 1,
};
const header_octets = try header.render(&wire);
@memcpy(wire[header_octets..][0..encoded.written], block[0..encoded.written]);
```

Both paths are taken from [`example/receive.zig`](example/receive.zig),
which builds a request split across a CONTINUATION frame and reads it back.
It is compiled and run as part of `zig build ci`.

Sizing is the caller's: the block buffer's length is the limit on a field
block and therefore the defence against a CONTINUATION flood, and the HPACK
storage size is the `SETTINGS_HEADER_TABLE_SIZE` you advertise.

## Design constraints

- **No allocator.** `std.mem.Allocator` does not appear in the public API or
  under `src/`. Every buffer is caller-owned and caller-sized.
- **No I/O.** No `std.Io`, `std.posix`, `std.net` or `std.fs` under `src/`.
  The build's lint step enforces this.
- **No connection state.** Flow control, stream states and SETTINGS
  negotiation are policy and differ between a proxy and a client, so they
  stay with the caller. Validation reports; it does not decide what to do
  about a malformed message.
- **Assertions are a build option.** On by default in every optimize mode,
  removed with `-Dassertions=false`. See [`src/assert.zig`](src/assert.zig).

## Building and testing

```sh
zig build ci                                             # fmt, unit tests, fuzz corpus, frame corpus, example, lint
zig build ci -Doptimize=ReleaseFast                      # release, assertions on
zig build ci -Doptimize=ReleaseFast -Dassertions=false   # release, assertions off
zig build fuzz --fuzz                                    # coverage-guided fuzzing
zig build bench                                          # decode and encode microbenchmarks
zig build fmt-fix                                        # reformat
```

CI runs the three `ci` invocations above on x86_64 and aarch64 Linux,
Windows and macOS.

## Documentation

- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md): the coding rules the lint and
  the review enforce.
- [corpus/README.md](corpus/README.md): the vendored frame fixtures and what
  they cover.

## License

[MIT](LICENSE)
