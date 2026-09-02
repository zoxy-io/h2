# Vendored corpus

MIT licensed and vendored byte-identical to upstream, so a diff against the
named commit is the whole audit.

It lives in its own test binary (`zig build corpus`) because it needs an
allocator and a JSON parser, and neither belongs in a package that promises no
allocator and ships no fixtures.

The HPACK interoperability corpus that used to sit beside this one went with
HPACK to [zoxy-io/hpack](https://github.com/zoxy-io/hpack), where
`zig build corpus` still runs it.

# HTTP/2 frame fixtures

Vendored from [http2jp/http2-frame-test-case](https://github.com/http2jp/http2-frame-test-case),
MIT licensed (`frames/LICENSE`). All 34 fixtures, because the whole corpus is
140 KiB — there is nothing to select.

Each fixture is one frame: a hex `wire`, and either a decoded `frame` or a
`null` frame with a list of RFC 9113 section 7 error codes the decode must
produce.

## What it covers

Twelve valid frames, one for every frame type RFC 9113 defines:

| type | fixture | notes |
|---|---|---|
| DATA | `data/normal` | padded |
| HEADERS | `headers/normal`, `headers/priority` | the second carries the priority fields and padding |
| PRIORITY | `priority/normal` | |
| RST_STREAM | `rst_stream/normal` | |
| SETTINGS | `settings/normal` | two parameters |
| PUSH_PROMISE | `push_promise/normal` | padded |
| PING | `ping/normal` | |
| GOAWAY | `goaway/normal` | with debug data |
| WINDOW_UPDATE | `window_update/normal` | |
| CONTINUATION | `continuation/normal`, `continuation/header` | |

And twenty-two error cases, which are the more valuable half. They map onto the
rules #2 lists almost one for one:

| rule | fixtures |
|---|---|
| padding at least the declared length | `data-frame-padding`, `headers-frame-padding`, `push_promise-frame-padding` |
| frame size fixed per type | `priority-`, `rst_stream-`, `ping-`, `window_update-`, `goaway-`, `data-frame-size` |
| SETTINGS a multiple of six, and empty when ACK | `settings-frame-size`, `settings-frame-ack-size` |
| stream identifier valid for the type | one per type: `data-`, `headers-`, `priority-`, `rst_stream-`, `settings-`, `push_promise-`, `ping-`, `goaway-frame-stream` |
| WINDOW_UPDATE increment non-zero | `window_update-frame-increment` |
| promised stream identifier even and non-zero | `push_promise-frame-promised_stream-odd`, `-zero` |

Every case names `PROTOCOL_ERROR` or `FRAME_SIZE_ERROR`, and
`push_promise-frame-padding` accepts either — which is itself worth knowing,
because it means the codec is not obliged to pick one and a test that demands a
single code would be wrong.

**Not covered:** unknown frame types, which RFC 9113 section 4.1 requires be
ignored rather than rejected; frames exceeding `SETTINGS_MAX_FRAME_SIZE`, since
a fixture cannot know what was negotiated; and the CONTINUATION flood, which is
a property of a sequence rather than of one frame. Those need tests this package
writes itself; the first two now have them in `src/frame/Header.zig`, and the
third waits on a connection layer.

Nor does any fixture record a failure's **severity** — whether it ends the
connection or only the stream. RFC 9113 makes a wrong-length PRIORITY frame a
stream error and a wrong-length RST_STREAM a connection error, and the corpus
names codes, not severities. `Header.severity` is covered by unit tests only.

## Status

`corpus/frames.zig` checks every fixture three ways: the codec's `Header.parse`
against the fixture's declared metadata, the codec against an independent
reading of the nine octets that was written before it and does not import it,
and `Header.validate` against the fixture's expected error codes.

**Seventeen of the twenty-two error cases are caught by the header alone**, and
the split is pinned in the test so it can only move deliberately. The five that
remain each need an octet of payload, and arrive with the payload codec:

| fixture | needs |
|---|---|
| `data-frame-padding`, `headers-frame-padding` | the pad length, checked against what is left |
| `push_promise-frame-promised_stream-odd`, `-zero` | the promised stream identifier's parity |
| `window_update-frame-increment` | the increment, which must not be zero |

`push_promise-frame-padding` is caught by the header, because a PADDED
PUSH_PROMISE shorter than five octets cannot hold both its pad length and its
promised stream identifier. It is also the fixture that accepts *two* error
codes, and the codec returns `FRAME_SIZE_ERROR` where a reader might expect
`PROTOCOL_ERROR` — which is why the test checks membership rather than
equality. A test written the obvious way would fail on it and be wrong.

Payload comparison is still absent: the fixtures carry decoded payloads
(`frame_payload`) that nothing yet reads.
