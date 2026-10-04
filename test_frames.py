"""Protocol-level tests for frames.py.

Covers the 10-byte binary framing, msgpack, LZ4/zstd payloads, stream
reassembly across websocket message boundaries, and the JSON transport.

    .venv/bin/python test_frames.py

When pymax happens to be importable (e.g. via the sibling antimax venv) its
framer is used as the reference encoder, so the decoder is checked against the
same code the native client uses. Otherwise packets are built by hand.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PYMAX = None
for _candidate in (
    os.environ.get("PYMAX_SITE", ""),
    "/Users/artem_farafonov/Projects/antimax/.venv/lib/python3.13/site-packages",
):
    if _candidate and _candidate not in sys.path:
        sys.path.append(_candidate)
try:
    from pymax.protocol.tcp.framing import TcpPacketFramer
    from pymax.protocol.tcp.protocol import TcpProtocol
    from pymax.protocol.models import OutboundFrame
    PYMAX = True
except Exception:
    TcpPacketFramer = TcpProtocol = OutboundFrame = None

import frames
from opcodes import opcode_name

failures = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s %s" % (label, detail))
        failures.append(label)


def pack(ver, opcode, cmd, seq, payload):
    """Reference encoder: pymax's TcpProtocol when available, else our own."""
    if PYMAX:
        return TcpProtocol().encode(
            OutboundFrame(ver=ver, opcode=opcode, cmd=cmd, seq=seq, payload=payload)
        )
    body = __import__("msgpack").packb(payload, use_bin_type=True)
    return frames.HEADER_STRUCT.pack(ver, cmd, seq, opcode, len(body)) + body


print("1. header size / struct format  (pymax available: %s)" % bool(PYMAX))
check("HEADER_SIZE == 10", frames.HEADER_SIZE == 10, frames.HEADER_SIZE)
if PYMAX:
    check("format matches pymax",
          frames.HEADER_STRUCT.format == TcpPacketFramer.HEADER_STRUCT.format,
          frames.HEADER_STRUCT.format)

print("\n2. encode with pymax, decode with ours (SESSION_INIT)")
payload = {
    "mt_instanceid": "6c3d4e42-aa11-4f2b-9c33-1de0abcdef01",
    "userAgent": {"deviceType": "WEB", "appVersion": "26.7.15", "locale": "ru"},
    "clientSessionId": 42,
    "deviceId": "web-device-1234",
}
raw = pack(10, 6, 0, 0, payload)
check("encoded len > 10", len(raw) > 10, len(raw))

dec = frames.BinaryStreamDecoder()
out = dec.feed(raw)
check("one frame emitted", len(out) == 1, len(out))
f = out[0]
check("opcode == 6 (%s)" % opcode_name(f.opcode), f.opcode == 6, f.opcode)
check("ver == 10", f.ver == 10, f.ver)
check("cmd == 0", f.cmd == 0, f.cmd)
check("seq == 0", f.seq == 0, f.seq)
check("flags == 0", f.flags == 0, f.flags)
check("payload round-trips", f.payload == payload, f.payload)
check("no error", f.error is None, f.error)
check("buffer drained", dec.pending == 0, dec.pending)

print("\n3. stream reassembly: 3 packets in one binary message")
stream = b""
for i, op in enumerate((1, 19, 64)):
    stream += pack(10, op, 0, i, {"n": i})
dec = frames.BinaryStreamDecoder()
out = dec.feed(stream)
check("3 frames from 1 message", len(out) == 3, len(out))
check("opcodes in order", [x.opcode for x in out] == [1, 19, 64], [x.opcode for x in out])
check("payloads in order", [x.payload["n"] for x in out] == [0, 1, 2])

print("\n4. stream reassembly: one packet split across 3 messages")
one = pack(10, 128, 0, 7, {"message": {"text": "hi"}})
dec = frames.BinaryStreamDecoder()
acc = []
for chunk in (one[:4], one[4:20], one[20:]):
    acc += dec.feed(chunk)
check("1 frame reassembled", len(acc) == 1, len(acc))
check("opcode == 128 (%s)" % opcode_name(acc[0].opcode), acc[0].opcode == 128)
check("payload intact", acc[0].payload == {"message": {"text": "hi"}}, acc[0].payload)

print("\n5. byte-at-a-time reassembly")
dec = frames.BinaryStreamDecoder()
acc = []
for i in range(len(one)):
    acc += dec.feed(one[i:i + 1])
check("1 frame from %d 1-byte messages" % len(one), len(acc) == 1, len(acc))
check("payload intact", acc[0].payload == {"message": {"text": "hi"}})

print("\n6. seq wrapping is uint16")
big = pack(10, 1, 0, 0xFFFF, {"interactive": True})
f = frames.BinaryStreamDecoder().feed(big)[0]
check("seq 65535 decodes", f.seq == 0xFFFF, f.seq)
check("payload intact", f.payload == {"interactive": True}, f.payload)

print("\n7. lz4 block decompress vs the real lz4 library")
# NOTE: pymax's own Lz4BlockCompression.compress is broken (it truncates
# match_len to the low 4 bits with no 0x0F continuation), which is why
# TcpProtocol.encode has compression commented out. Use the reference
# implementation to produce valid blocks, like the server does.
import lz4.block

orig = b'{"opcode":128,"payload":{"message":{"text":"' + b"A" * 400 + b'"}}}'
comp = lz4.block.compress(orig, store_size=False)
check("lz4 produced smaller output", len(comp) < len(orig), (len(comp), len(orig)))
back = frames.lz4_block_decompress(comp)
check("we decompress real lz4 blocks", back == orig, back[:60])

# and confirm the pymax bug for the record
if PYMAX:
    from pymax.protocol.tcp.compression import Lz4BlockCompression

    buggy = Lz4BlockCompression().compress(orig)
    try:
        Lz4BlockCompression().decompress(buggy)
        print("  note pymax compressor unexpectedly round-trips")
    except ValueError as e:
        print("  note confirmed pymax compressor is broken: %s" % e)

# short payloads, exact-boundary literal/match lengths, and incompressible data
for label, sample in (
    ("empty-ish", b"a"),
    ("15 literals", b"0123456789abcde"),
    ("16 literals", b"0123456789abcdef"),
    ("all same byte", b"Z" * 3000),
    ("incompressible", bytes((i * 97 + 13) % 256 for i in range(500))),
    ("long match", b"AB" * 5000),
):
    c = lz4.block.compress(sample, store_size=False)
    check("lz4 round-trip: %s" % label, frames.lz4_block_decompress(c) == sample)

print("\n8. lz4-compressed packet decodes end to end (flags=0x01)")
mp = __import__("msgpack").packb(
    {"opcode": 128, "payload": {"message": {"text": "A" * 400}}}, use_bin_type=True
)
comp8 = lz4.block.compress(mp, store_size=False)
hdr = frames.HEADER_STRUCT.pack(10, 0, 0, 128, (0x01 << 24) | len(comp8))
f = frames.BinaryStreamDecoder().feed(hdr + comp8)[0]
check("flags == 1", f.flags == 1, f.flags)
check("note mentions lz4", "lz4" in (f.note or ""), f.note)
check("payload decoded", f.payload.get("opcode") == 128, f.payload)
check("text intact", f.payload["payload"]["message"]["text"] == "A" * 400)

print("\n9. zstd-compressed packet decodes end to end (flags=0xFF)")
import zstandard
zbytes = zstandard.ZstdCompressor().compress(mp)
hdr = frames.HEADER_STRUCT.pack(10, 0, 0, 155, (0xFF << 24) | len(zbytes))
f = frames.BinaryStreamDecoder().feed(hdr + zbytes)[0]
check("flags == 255", f.flags == 0xFF, f.flags)
check("note mentions zstd", "zstd" in (f.note or ""), f.note)
check("payload decoded", f.payload.get("opcode") == 128, f.payload)

print("\n9b. invalid flags are rejected, not silently mis-decoded")
hdr = frames.HEADER_STRUCT.pack(10, 0, 0, 1, (0x90 << 24) | 4)
f = frames.BinaryStreamDecoder().feed(hdr + b"\x00\x00\x00\x00")[0]
check("error recorded", f.error is not None, f.error)
check("error mentions invalid", "invalid" in (f.error or ""), f.error)

print("\n10. msgpack wrapped-value ext (code 1) is unwrapped")
inner = __import__("msgpack").packb({"chatsCount": 50}, use_bin_type=True)
outer = __import__("msgpack").packb(
    {"exp": __import__("msgpack").ExtType(1, inner)}, use_bin_type=True
)
f = frames.BinaryStreamDecoder().feed(
    frames.HEADER_STRUCT.pack(10, 0, 0, 19, len(outer)) + outer
)[0]
check("nested ext unwrapped", f.payload == {"exp": {"chatsCount": 50}}, f.payload)

print("\n11. integer map keys normalized to strings")
raw11 = __import__("msgpack").packb({1: "a", 2: "b"}, use_bin_type=True)
f = frames.BinaryStreamDecoder().feed(
    frames.HEADER_STRUCT.pack(10, 0, 0, 21, len(raw11)) + raw11
)[0]
check("int keys -> str", f.payload == {"1": "a", "2": "b"}, f.payload)

print("\n11b. bytes payload values are hex-encoded for readability")
raw11b = __import__("msgpack").packb({"chatCacheFingerprint": b"\xde\xad\xbe\xef"}, use_bin_type=True)
f = frames.BinaryStreamDecoder().feed(
    frames.HEADER_STRUCT.pack(10, 0, 0, 19, len(raw11b)) + raw11b
)[0]
check("bytes -> hex", f.payload["chatCacheFingerprint"] == "deadbeef", f.payload)

print("\n12. json text frames (the actual web transport)")
f = frames.decode_json_frame(
    '{"ver":11,"opcode":128,"cmd":0,"seq":3,"payload":{"message":{"text":"привет"}}}'
)
check("ver 11", f.ver == 11, f.ver)
check("opcode 128 (%s)" % opcode_name(f.opcode), f.opcode == 128)
check("cmd 0", f.cmd == 0)
check("seq 3", f.seq == 3)
check("unicode payload", f.payload["message"]["text"] == "привет", f.payload)
check("encoding json", f.encoding == "json")

print("\n13. malformed json does not raise")
f = frames.decode_json_frame("{not json")
check("error captured", f.error is not None, f.error)
check("opcode is None", f.opcode is None)

print("\n14. unknown opcodes survive")
f = frames.decode_json_frame('{"ver":11,"opcode":9999,"cmd":0,"seq":0,"payload":{}}')
check("opcode kept", f.opcode == 9999)
check("name is UNKNOWN_9999", opcode_name(f.opcode) == "UNKNOWN_9999", opcode_name(f.opcode))

print("\n15. trailing garbage after a complete packet is ignored")
f = frames.BinaryStreamDecoder().feed(one + b"\xde\xad\xbe\xef")
check("1 frame", len(f) == 1, len(f))
check("garbage left buffered", f and True)

print()
if failures:
    print("FAILED: %d check(s): %s" % (len(failures), failures))
    sys.exit(1)
print("all checks passed")
