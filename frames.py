"""MAX frame decoding: the 10-byte binary framing, plus JSON for completeness.

Verified against the live web client on 2026-10-04: `web.max.ru` speaks the
*same* binary protocol as the native TCP client, over the websocket. Every
frame is a 10-byte big-endian header followed by a msgpack payload, LZ4
compressed by default, with `ver=10`. There is no JSON on the wire. JSON frames
are still decoded here because pymax has a `ver=11` JSON protocol for its own
WebClient, and it costs nothing to accept both.

Binary header (10 bytes, struct format ">BBHHI"):

    offset  size  field
    0       1     ver       protocol version (10 = what the live client sends)
    1       1     cmd       0 request, 1 response, 2 event, 3 error
    2       2     seq       uint16 request correlation id, wraps at 0x10000
    4       2     opcode    see opcodes.py
    6       4     packed    (flags << 24) | (payload_len & 0xFFFFFF)
    10      N     payload   msgpack map, LZ4/zstd compressed per `flags`

The high byte of the length word is the `flags` field and selects the payload
compression: 0x00 raw msgpack, 0x01-0x7F LZ4 block with the flag as the
compression factor, 0xFF zstd. Live traffic is almost always LZ4.

A websocket message does not necessarily line up with one protocol packet, so
BinaryStreamDecoder buffers and reassembles across message boundaries.
"""

import json
import struct

import msgpack

HEADER_STRUCT = struct.Struct(">BBHHI")
HEADER_SIZE = HEADER_STRUCT.size

FLAG_RAW = 0x00
FLAG_ZSTD = 0xFF
LEN_MASK = 0x00FFFFFF

# msgpack ext type 1 is MAX's "wrapped value": an ext whose body is itself a
# msgpack object, unwrapped recursively. Mirrors pymax MsgpackPayloadCodec.
WRAPPED_VALUE_EXT_CODE = 1


def _decode_ext(code, data):
    if code != WRAPPED_VALUE_EXT_CODE:
        return msgpack.ExtType(code, data)
    return msgpack.unpackb(data, raw=False, strict_map_key=False, ext_hook=_decode_ext)


def decompress(payload, flags):
    """Unpack a binary payload according to its `flags` compression byte."""
    if flags == FLAG_ZSTD:
        import zstandard

        with zstandard.ZstdDecompressor().stream_reader(_BytesReader(payload)) as reader:
            return reader.read()
    if flags > 0x7F:
        raise ValueError("invalid compression flags: 0x%02X" % flags)
    if flags > FLAG_RAW:
        return lz4_block_decompress(payload)
    return payload


class _BytesReader:
    """Minimal file-like wrapper so zstandard can stream from a bytes object."""

    def __init__(self, data):
        self._data = data
        self._pos = 0

    def read(self, size=-1):
        if size is None or size < 0:
            chunk = self._data[self._pos:]
        else:
            chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk

    def close(self):
        pass


def lz4_block_decompress(src, max_output=64 * 1024 * 1024):
    """Decompress a raw LZ4 block (no 04 22 4D 18 magic, no length prefix)."""
    dst = bytearray()
    pos = 0
    src_len = len(src)

    while pos < src_len:
        token = src[pos]
        pos += 1

        lit_len = token >> 4
        if lit_len == 15:
            while pos < src_len:
                byte = src[pos]
                pos += 1
                lit_len += byte
                if byte != 255:
                    break

        if lit_len > 0:
            if pos + lit_len > src_len:
                raise ValueError("lz4: literal length out of bounds")
            dst += src[pos:pos + lit_len]
            pos += lit_len
            if len(dst) > max_output:
                raise ValueError("lz4: output too large")

        if pos >= src_len:
            break
        if pos + 1 >= src_len:
            raise ValueError("lz4: incomplete match offset")

        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if offset == 0:
            raise ValueError("lz4: zero match offset")

        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 0x0F:
            while pos < src_len:
                byte = src[pos]
                pos += 1
                match_len += byte
                if byte != 255:
                    break

        match_pos = len(dst) - offset
        if match_pos < 0:
            raise ValueError("lz4: match out of bounds")
        for i in range(match_len):
            dst.append(dst[match_pos + (i % offset)])

        if len(dst) > max_output:
            raise ValueError("lz4: output too large")

    return bytes(dst)


def _normalize_keys(value):
    """MAX allows integer and bytes map keys; make them JSON-friendly."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if isinstance(key, int):
                key = str(key)
            elif isinstance(key, bytes):
                try:
                    key = key.decode("utf-8")
                except UnicodeDecodeError:
                    key = key.hex()
            out[key] = _normalize_keys(item)
        return out
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_keys(item) for item in value]
    if isinstance(value, msgpack.ExtType):
        return "<ext type=%d len=%d>" % (value.code, len(value.data))
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return value


def decode_msgpack(payload_bytes):
    """msgpack -> python, tolerating trailing bytes and wrapped-value exts."""
    if not payload_bytes:
        return {}
    try:
        return _normalize_keys(
            msgpack.unpackb(
                payload_bytes, raw=False, strict_map_key=False, ext_hook=_decode_ext
            )
        )
    except msgpack.exceptions.ExtData as err:
        return _normalize_keys(err.unpacked)
    except msgpack.UnpackException as err:
        raise ValueError("msgpack decode failed: %s" % err) from err


class MaxFrame:
    """One decoded MAX protocol frame."""

    def __init__(self, ver, cmd, seq, opcode, flags, payload, raw, encoding, direction):
        self.ver = ver
        self.cmd = cmd
        self.seq = seq
        self.opcode = opcode
        self.flags = flags
        self.payload = payload
        self.raw = raw
        self.encoding = encoding
        self.direction = direction
        self.note = None
        self.error = None
        self.ws_url = None
        self.ws_id = None
        self.ts = None

    @property
    def size(self):
        return len(self.raw) if isinstance(self.raw, (bytes, bytearray)) else len(
            str(self.raw or "")
        )

    def to_dict(self, redact=None):
        from opcodes import command_name, opcode_name

        payload = self.payload
        if redact is not None:
            payload = redact(payload)
        return {
            "ts": self.ts,
            "ws_url": self.ws_url,
            "ver": self.ver,
            "cmd": command_name(self.cmd),
            "seq": self.seq,
            "opcode": self.opcode,
            "opcode_name": opcode_name(self.opcode),
            "flags": self.flags,
            "encoding": self.encoding,
            "direction": self.direction,
            "size": self.size,
            "note": self.note,
            "error": self.error,
            "payload": payload,
        }


def _pick(d, *names, default=None):
    for name in names:
        if isinstance(d, dict) and name in d and d[name] is not None:
            return d[name]
    return default


def decode_json_frame(text, direction="recv", ws_url=None, ws_id=None):
    """Decode a websocket text frame. MAX sends {"ver":11,...} as JSON."""
    raw = text
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        frame = MaxFrame(None, None, None, None, 0, None, raw, "json", direction)
        frame.error = "json decode failed: %s" % err
        frame.ws_url = ws_url
        frame.ws_id = ws_id
        return frame

    if not isinstance(data, dict):
        frame = MaxFrame(None, None, None, None, 0, data, raw, "json", direction)
        frame.note = "non-object frame"
        frame.ws_url = ws_url
        frame.ws_id = ws_id
        return frame

    frame = MaxFrame(
        ver=_pick(data, "ver"),
        cmd=_pick(data, "cmd"),
        seq=_pick(data, "seq"),
        opcode=_pick(data, "opcode"),
        flags=0,
        payload=_pick(data, "payload", default={}),
        raw=raw,
        encoding="json",
        direction=direction,
    )
    frame.ws_url = ws_url
    frame.ws_id = ws_id
    return frame


class BinaryStreamDecoder:
    """Reassembles MAX binary packets from a stream of websocket binary frames.

    A websocket message does not have to line up with a protocol packet: one
    message may carry several packets, or half of one. This buffers bytes and
    emits every complete packet it can parse.
    """

    def __init__(self, direction="recv", ws_url=None, ws_id=None):
        self._buf = bytearray()
        self._direction = direction
        self._ws_url = ws_url
        self._ws_id = ws_id
        self.packets = 0
        self.bytes_in = 0
        self.stalled = False

    def feed(self, data):
        """Add bytes, return the list of complete frames now available."""
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        self._buf += data
        self.bytes_in += len(data)

        out = []
        while True:
            if len(self._buf) < HEADER_SIZE:
                break

            ver, cmd, seq, opcode, packed = HEADER_STRUCT.unpack_from(self._buf, 0)
            flags = (packed >> 24) & 0xFF
            payload_len = packed & LEN_MASK
            total = HEADER_SIZE + payload_len

            if len(self._buf) < total:
                # Wait for the rest of the packet. A single trailing frame that
                # never completes means the stream is not raw MAX framing.
                self.stalled = len(self._buf) > 0
                break

            header = bytes(self._buf[:HEADER_SIZE])
            body = bytes(self._buf[HEADER_SIZE:total])
            del self._buf[:total]
            self.packets += 1
            out.append(self._build(ver, cmd, seq, opcode, flags, header + body, body))

        self.stalled = False
        return out

    def _build(self, ver, cmd, seq, opcode, flags, raw, body):
        frame = MaxFrame(ver, cmd, seq, opcode, flags, None, raw, "binary", self._direction)
        frame.ws_url = self._ws_url
        frame.ws_id = self._ws_id
        try:
            plain = decompress(body, flags)
            frame.payload = decode_msgpack(plain)
            if flags != FLAG_RAW:
                frame.note = "payload %s-compressed" % ("zstd" if flags == FLAG_ZSTD else "lz4")
        except Exception as err:
            frame.error = "%s: %s" % (type(err).__name__, err)
            frame.payload = {"_raw_hex": body[:64].hex()}
        return frame

    @property
    def pending(self):
        return len(self._buf)
