# max-reverse

Reverse-engineer the MAX messenger (max.ru) by opening the real web client in
Chrome, logging in by hand, and decoding every websocket frame it sends and
receives. JavaScript bundles are saved alongside so you can grep the client
code for opcodes, endpoints, and field names.

```
./run.sh
```

That launches Chrome, opens `web.max.ru`, and starts printing decoded traffic.
Log in (QR or phone) in the browser window; traffic is captured from the moment
the page opens, so the whole auth handshake is included.

## What it prints

```
─── max-reverse sniffer ───
18:30:07 chrome     /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
18:30:07 url        https://web.max.ru/
18:30:07 capture    captures/max_20261004_183007.jsonl  (credentials redacted)

─── log into MAX in the Chrome window ───
18:30:08 socket open wss://api.oneme.ru/websocket

 → REQUEST  seq=0     op=6    SESSION_INIT 344B
    payload lz4-compressed
    keys=[deviceId,userAgent]
    {
      "userAgent": {
        "deviceType": "WEB",
        "pushDeviceType": "WEBPUSH",
        "appVersion": "26.10.1",
        "deviceName": "Chrome",
        "headerUserAgent": "Mozilla/5.0 (Macintosh; ...)",
        "screen": "720x1280 1.0x",
        "timezone": "Europe/Istanbul"
      },
      "deviceId": "10984d3d-ac32-4992-838c-7e1866fab5e8"
    }

 ← RESPONSE seq=0     op=6    SESSION_INIT 212B
    payload lz4-compressed
    keys=[lang,location,phone-auth-enabled,reg-country-code,web-pwa-promo]
```

`→` is client to server, `←` is server to client. On exit you get a summary
with the top opcodes and counts per direction, and any opcode the sniffer saw
that is missing from the table.

## Flags

| flag | effect |
|---|---|
| `-v`, `--verbose` | print every frame, not just the interesting ones |
| `--full` | print payloads in full instead of truncating at ~1400 chars |
| `--no-sends` | only print inbound frames |
| `--no-redact` | write credentials into the capture file too (see below) |
| `--no-js` | skip saving JavaScript bundles |
| `--http` | print every POST/PUT, not just uploads (noisy) |
| `--no-intercept` | don't intercept HTTP, keeping the browser cache warm (costs you upload filenames and sizes) |
| `--url URL` | open something other than `web.max.ru` |
| `--devtools-port N` | CDP port to attach real devtools (default 9333) |

## Output files

- `captures/max_<timestamp>.jsonl` — one JSON object per frame: timestamp,
  direction, `ver`, `cmd`, `seq`, `opcode`, `opcode_name`, `size`, decoded
  `payload`.
- `js/` — the web client's JavaScript bundles, named after their URL.
- `chrome_profile_max/` — persistent Chrome profile, so you only log in once.

### Redaction

By default `token`, `verifyCode`, `password`, `chatCacheFingerprint` and
similar keys are replaced with `<redacted N chars>` both on screen and in the
capture file. Raw frame bytes are *not* written to the capture file in this
mode, because the SMS code is present in the raw frame too.

`--no-redact` stores everything including raw bytes, so you can pull your own
session `token` out of the `LOGIN` (opcode 19) request and reuse it to skip SMS
on the next login. Those files are secrets — `captures/` is gitignored.

## Media uploads (photo, video, file)

Media never travels over the websocket. Sending a photo is three separate
steps, and a websocket-only sniffer shows you only the last one — which is
exactly why `photoToken` appears out of nowhere in `MSG_SEND`:

```
phase 1  WS    PHOTO_UPLOAD (80)   -> {"url": "https://…&photoIds=40000000001"}
phase 2  HTTP  POST multipart/form-data to that presigned url
                                -> {"photos": {"40000000001": {"token": "…"}}}
phase 3  WS    MSG_SEND (64)      -> attaches: [{"_type": "PHOTO", "photoToken": "<phase 2 token>"}]
```

The sniffer captures all three, matches them by media id, and labels them:

```
   phase 1/3 PHOTO_UPLOAD  ids=40000000001  -> presigned url
 ← REQUEST  seq=51  op=80  PHOTO_UPLOAD 61B
    url=https://u.oneme.ru/upload?photoIds=40000000001&expires=…  ids=[40000000001]

   phase 2/3 HTTP POST  multipart/form-data 4.2MB image.jpeg image/jpeg  id=40000000001
POST   https://u.oneme.ru/upload?photoIds=40000000001&…
    sent 4.2MB  image.jpeg image/jpeg
200 POST https://u.oneme.ru/upload?photoIds=40000000001&…
    media id=40000000001
    {"photos": {"40000000001": {"token": "TESTTOKEN_AAAAAAAAAAAAAAAA…"}}}
   phase 2/3 done token(s):  40000000001=TESTTOKEN_AAAAAAA…

 → REQUEST  seq=52  op=64  MSG_SEND 345B
   phase 3/3 MSG_SEND PHOTO  id=40000000001  token matches phase 2
    attach=[PHOTO]
```

The image bytes themselves are summarised (size, filename, content type) and
never printed or written to the capture file.

Two details worth knowing:

- **Interception is armed after the page loads.** Playwright only populates
  `request.post_data_buffer` for requests it is actively intercepting — with no
  routes registered, an upload POST comes back with no body and you lose the
  filename and size. Registering a route makes Playwright disable the HTTP
  cache, so the sniffer arms a catch-all `continue_()` route *after* the initial
  page load, keeping the first paint cached. `--no-intercept` turns it off.
- **The token in the `MSG_SEND` *response* is different** from the one in the
  request. The request carries the token phase 2 handed back; the response
  carries a freshly issued one plus `photoId`, `width`, `height`, `baseUrl` and
  `thumbhash`. Correlation therefore matches on the request side.

Note also that MAX serialises the attachment kind as `_type`, not `type`
(pymax maps `AttachmentType.type` onto the `_type` wire alias), which is why an
attachment summary can look like `attach=[?]` if you only look for `type`.

## Grepping the web client

The bundles in `js/` are the actual client, unminified only in the sense that
they are as-shipped. Useful starting points:

```bash
# find the opcode table
grep -ro "NOTIF_MESSAGE\|MSG_SEND" js/ | head

# find websocket endpoints and api paths
grep -roh "wss://[^\"']*\|/api/[a-z0-9/_-]*" js/ | sort -u | head -40

# field names used on the wire
grep -roh "chatCacheFingerprint\|callsSeed\|prevMessageId" js/ | sort | uniq -c

# which bundle handles a given opcode number
grep -rl "288" js/
```

## What the protocol turned out to be

Verified against live traffic on 2026-10-04, not just read off pymax's source:

- **Transport** `wss://api.oneme.ru/websocket`. Despite being a websocket, the
  web client sends the *same binary protocol* as the native TCP client. There is
  no JSON on the wire. (pymax ships a `ver=11` JSON protocol for its own
  `WebClient`; nothing on the live wire uses it.)
- **Framing** 10-byte big-endian header, `struct ">BBHHI"`:
  `ver(1) cmd(1) seq(2, uint16) opcode(2) packed_len(4)`, then the payload.
  `packed_len` is `(flags << 24) | (payload_len & 0xFFFFFF)`.
- **Version** `ver=10` on the live wire.
- **Payload** msgpack map, **LZ4 block compressed** in practice. `flags` selects
  it: `0x00` raw, `0x01`–`0x7F` LZ4 with the flag as the compression factor,
  `0xFF` zstd.
- **Commands** `0` request, `1` response, `2` event, `3` error. Request/response
  correlate on the uint16 `seq`; server pushes arrive as `cmd=0` with a
  server-chosen `seq`.
- **No application-level crypto.** Confidentiality is TLS only. msgpack ext type
  `1` is a "wrapped value" (an ext whose body is another msgpack object), which
  is how `LOGIN` smuggles `exp`.
- **Opcodes** 177 of them, generated into `opcodes.py` from pymax 2.4.0's
  `pymax/protocol/enums.py`.
- **Login flow** `GET_QR` (288) returns a `qrLink` you open in the MAX app; the
  web app then polls `GET_QR_STATUS` (289). Phone login instead runs
  `AUTH_REQUEST` (17) → `AUTH` (18) → `LOGIN` (19) → `LOGIN2` (8).
- **Web clients skip the APK attestation.** The native client sends a 96-byte
  SHA-256 fingerprint (`mode` / `chatCacheFingerprint`) seeded by the server's
  `callsSeed`; with `deviceType: WEB` those fields are simply absent.
- **Keepalive** `PING` (1) every 30s, request/response.

## Layout

| file | role |
|---|---|
| `sniffer.py` | entrypoint: launches Chrome, hooks websockets + HTTP, logs both directions |
| `frames.py` | frame decoding: binary framing, stream reassembly, msgpack, LZ4/zstd |
| `opcodes.py` | generated opcode + command tables |
| `render.py` | console formatting, redaction, per-opcode summaries |
| `test_frames.py` | protocol tests (framing, compression, reassembly) |
| `test_offline.py` | render/redact/capture tests, prints a simulated session |
| `test_e2e.py` | real Chrome against a local mock MAX server: binary frames + upload |

## Tests

```bash
.venv/bin/python test_frames.py    # protocol layer
.venv/bin/python test_offline.py   # rendering, redaction, capture output
.venv/bin/python test_e2e.py       # full pipeline in a real browser (local mock server)
```

`test_e2e.py` runs real Chrome against a mock MAX server on localhost that
speaks the genuine framing (10-byte header, LZ4 msgpack, `ver=10`) and drives a
real multipart upload, so the browser-side hooks, the binary decoder, and the
three-phase upload correlation are all exercised without touching max.ru or
sending anything to a real account. It needs `websockets` and `lz4`, which are
only test-time dependencies.

`test_frames.py` cross-checks the decoder against pymax's own framer when pymax
happens to be importable (it looks in the sibling `antimax` venv), and builds
packets by hand otherwise. It also documents an upstream bug: pymax's
`Lz4BlockCompression.compress` truncates long matches without the `0x0F`
continuation encoding, so its output cannot be read back by its own decompressor.
That is why `TcpProtocol.encode` has compression commented out. Only the
decompress path is used in practice.

## Limitations

- Websockets created inside a Web Worker, SharedWorker, or Service Worker are
  not captured — Playwright's page-level `websocket` event only sees the page
  and its frames. Live MAX traffic is on the main page, so this has not come up;
  if it ever does, the fix is a raw CDP client that auto-attaches to worker
  targets.
- Arming request interception makes Chrome emit some requests twice (both the
  Fetch-paused and the network-level event). Identical
  `(method, url, size)` pairs within 2s are collapsed.
- A force-killed sniffer (`kill -9`) leaves Chrome running: Playwright's node
  driver survives and keeps the profile locked, so the next launch hangs or
  silently attaches to the stale window. Use Ctrl-C. If you already did, quit
  the stray Chrome window; the sniffer also auto-picks a free devtools port and
  warns when the profile is still held.
- The opcode table is a snapshot of pymax 2.4.0. MAX ships new opcodes
  regularly; the summary flags any it sees that aren't in `opcodes.py`.
- `captures/` and `js/` are gitignored and can contain personal data.
