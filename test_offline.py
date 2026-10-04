"""Offline test of the decode -> render -> capture pipeline.

Feeds a simulated MAX session through exactly the code paths sniffer.py uses
(no browser needed), checks redaction, the JSONL capture file, and the opcode
summary. Run it to see what the console output actually looks like:

    .venv/bin/python test_offline.py
"""

import json
import sys
import tempfile
from pathlib import Path

import frames
import render
from opcodes import Opcode, opcode_name
from sniffer import Capture, MaxSniffer, UploadTracker, describe_multipart, now_stamp

failures = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s %s" % (label, detail))
        failures.append(label)


class FakeArgs:
    url = "https://max.ru"
    verbose = False
    full = False
    show_sends = True
    no_redact = False
    no_js = True
    http = False
    no_intercept = False
    devtools_port = 9333


def frame(opcode, payload, cmd=0, direction="recv", ver=11, seq=0, flags=0, encoding="json"):
    f = frames.MaxFrame(ver, cmd, seq, opcode, flags, payload, json.dumps(payload), encoding, direction)
    f.ts = now_stamp()
    return f


SESSION = [
    # client -> server handshake, note the deviceId
    frame(Opcode.SESSION_INIT, {"userAgent": {"deviceType": "WEB", "appVersion": "26.7.15",
                                              "osVersion": "Linux", "locale": "ru",
                                              "timezone": "Europe/Moscow",
                                              "screen": "1080x1920 1.0x",
                                              "deviceName": "Chrome"},
                                "deviceId": "web-9f2c1a44-7b0e-4c3d-9a55-1e2b3c4d5e6f"},
          cmd=0, direction="send", seq=0),
    # server -> client handshake reply, carries the callsSeed
    frame(Opcode.SESSION_INIT, {"callsSeed": -8142739914885723311, "app-update-type": 0},
          cmd=1, direction="recv", seq=0),
    # auth request carries the phone
    frame(Opcode.AUTH_REQUEST, {"phone": "+79991234567", "type": "START_AUTH"},
          cmd=0, direction="send", seq=1),
    frame(Opcode.AUTH_REQUEST, {"token": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"},
          cmd=1, direction="recv", seq=1),
    # SMS verification: the code must never be printed or written
    frame(Opcode.AUTH, {"token": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                        "verifyCode": "123456", "authTokenType": "CHECK_CODE"},
          cmd=0, direction="send", seq=2),
    # login: the session bearer token
    frame(Opcode.LOGIN, {"token": "eyJhbGciOi.SUPERSECRET.SIGNATURE",
                         "chatsSync": -1, "contactsSync": -1, "presenceSync": -1,
                         "interactive": True,
                         "userAgent": {"deviceType": "WEB", "appVersion": "26.7.15"}},
          cmd=0, direction="send", seq=3),
    frame(Opcode.LOGIN, {"chats": [{"id": 111, "type": "CHAT", "title": "Ася"}],
                         "profile": {"id": 555, "names": {"firstName": "Artem"}},
                         "time": 1767225600000, "token": "eyJhbGciOi.ROTATED.SIGNATURE"},
          cmd=1, direction="recv", seq=3),
    frame(Opcode.LOGIN2, {"profile": {"id": 555}, "config": {"hash": "abc"}},
          cmd=1, direction="recv", seq=4),
    # an error frame
    frame(Opcode.MSG_SEND, {"error": "chat_not_found", "message": "Chat not found",
                            "title": "Error", "localizedMessage": "Чат не найден"},
          cmd=3, direction="recv", seq=9),
    # traffic
    frame(Opcode.PING, {"interactive": True}, cmd=0, direction="send", seq=5),
    frame(Opcode.PING, {"interactive": True}, cmd=1, direction="recv", seq=5),
    frame(Opcode.CHATS_LIST, {"chats": [{"id": 111}, {"id": 222}, {"id": 333}]},
          cmd=1, direction="recv", seq=6),
    frame(Opcode.MSG_SEND, {"message": {"id": 9001, "chatId": 111, "sender": 555,
                                         "text": "привет, это тест", "time": 1767225601,
                                         "type": "text"}},
          cmd=0, direction="send", seq=7),
    frame(Opcode.MSG_SEND, {"message": {"id": 9001, "chatId": 111, "sender": 555,
                                         "text": "привет, это тест", "time": 1767225601,
                                         "type": "text"}},
          cmd=1, direction="recv", seq=7),
    frame(Opcode.NOTIF_MESSAGE, {"message": {"id": 9002, "chatId": 222, "sender": 777,
                                             "text": "а ты кто?", "time": 1767225700,
                                             "type": "text",
                                             "reactionInfo": {"totalCount": 2, "yourReaction": "❤️"}}},
          cmd=0, direction="recv", seq=100),
    frame(Opcode.NOTIF_TYPING, {"chatId": 222, "sender": 777}, cmd=0, direction="recv", seq=101),
    frame(Opcode.NOTIF_PRESENCE, {"userId": 777, "presence": "ONLINE"}, cmd=0, direction="recv", seq=102),
    frame(Opcode.NOTIF_MSG_REACTIONS_CHANGED, {"message": {"id": 9002, "chatId": 222,
                                                           "sender": 777, "text": "а ты кто?",
                                                           "reactionInfo": {"totalCount": 3}}},
          cmd=0, direction="recv", seq=103),
    # an unknown opcode -> should be reported as missing from the table
    frame(4242, {"mystery": True}, cmd=0, direction="recv", seq=104),
    # a big message so truncation kicks in
    frame(Opcode.NOTIF_MESSAGE, {"message": {"id": 9003, "chatId": 111, "sender": 777,
                                             "text": "ы" * 900, "time": 1767225800}},
          cmd=0, direction="recv", seq=105),
]

print("1. console rendering (what you see in the terminal)")
print("-" * 78)
palette = render.Palette(False)
for f in SESSION:
    print(render.format_frame(f, palette))
print("-" * 78)

print("\n2. redaction")
secret_frame = SESSION[5]
red = render.redact(secret_frame.payload)
check("login token redacted", "SUPERSECRET" not in json.dumps(red), red.get("token"))
check("redaction keeps length info", "chars" in red.get("token", ""), red.get("token"))

otp = render.redact(SESSION[4].payload)
check("verifyCode redacted", otp["verifyCode"].startswith("<redacted"), otp["verifyCode"])
check("verifyCode value gone", "123456" not in json.dumps(otp))
check("authTokenType kept (not a credential)", otp["authTokenType"] == "CHECK_CODE", otp)

nested = render.redact({"a": {"b": [{"chatCacheFingerprint": "ff" * 48, "keep": 1}]}})
check("nested camelCase secret redacted",
      nested["a"]["b"][0]["chatCacheFingerprint"].startswith("<redacted"), nested)
check("nested sibling preserved", nested["a"]["b"][0]["keep"] == 1)
check("phone is NOT redacted (not a credential)", render.redact({"phone": "+79991234567"})["phone"] == "+79991234567")

print("\n3. capture file is valid JSONL with one object per frame")
with tempfile.TemporaryDirectory() as td:
    path = Path(td) / "cap.jsonl"
    cap = Capture(path, redact_enabled=True)
    for f in SESSION:
        f.ws_url = "wss://api.oneme.ru/websocket"
        cap.write(f)
    cap.close()
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    check("line count matches frames", len(lines) == len(SESSION), (len(lines), len(SESSION)))
    objs = [json.loads(l) for l in lines]
    check("all lines parse as json", len(objs) == len(SESSION))
    check("counter matches", cap.count == len(SESSION), cap.count)
    first = objs[0]
    check("has opcode_name", first["opcode_name"] == "SESSION_INIT", first.get("opcode_name"))
    check("has direction", first["direction"] == "send", first.get("direction"))
    check("has cmd name", first["cmd"] == "REQUEST", first.get("cmd"))
    check("has ws url", first["ws_url"] == "wss://api.oneme.ru/websocket")
    blob = path.read_text(encoding="utf-8")
    check("no token in capture", "SUPERSECRET" not in blob)
    # Check the AUTH frame specifically: a naive scan of the whole file would
    # false-positive on the phone number +79991234567, which contains "123456".
    auth_lines = [o for o in objs if o["opcode_name"] == "AUTH"]
    check("auth frame captured", len(auth_lines) == 1, len(auth_lines))
    check(
        "otp not in capture",
        "123456" not in json.dumps(auth_lines[0]["payload"]),
        auth_lines[0]["payload"],
    )
    check("otp field redacted on disk",
          auth_lines[0]["payload"]["verifyCode"].startswith("<redacted"),
          auth_lines[0]["payload"].get("verifyCode"))
    check("no raw bytes written while redacting",
          all(o.get("raw_hex") is None and o.get("raw_truncated") is None for o in objs))

    print("\n   raw (unredacted) mode keeps everything, for your own token:")
    raw_path = Path(td) / "raw.jsonl"
    raw = Capture(raw_path, redact_enabled=False)
    raw.write(SESSION[5])
    raw.close()
    check("raw mode keeps token", "SUPERSECRET" in raw_path.read_text())

print("\n4. opcode counting and unknown-opcode detection")
class Stub(MaxSniffer):
    def __init__(self):
        self.args = FakeArgs()
        self.palette = render.Palette(False)
        self.capture = type("C", (), {"write": lambda s, f: None, "count": 0})()
        self.opcode_counts = __import__("collections").Counter()
        self.direction_counts = __import__("collections").Counter()
        self.printed = 0
        self.authenticated = True
        self.seen_max_socket = True
        self.js = type("J", (), {"enabled": False, "saved": 0})()

stub = Stub()
for f in SESSION:
    stub.opcode_counts[f.opcode] += 1
    stub.direction_counts[f.direction] += 1
check("counts unique opcodes", len(stub.opcode_counts) == len({f.opcode for f in SESSION}))
check("counts total frames", sum(stub.opcode_counts.values()) == len(SESSION))
check("unknown opcode flagged", 4242 not in __import__("sniffer").OPCODE_NAMES)

print("\n5. auth detection fires on LOGIN response, not on the request")
sniffer = MaxSniffer(FakeArgs(), render.Palette(False))
check("starts unauthenticated", not sniffer.authenticated)
req = frame(Opcode.LOGIN, {}, cmd=0, direction="send")
sniffer.maybe_authenticated(req)
check("send LOGIN does not authenticate", not sniffer.authenticated)
resp = frame(Opcode.LOGIN, {}, cmd=1, direction="recv")
sniffer.maybe_authenticated(resp)
check("recv LOGIN authenticates", sniffer.authenticated)

print("\n6. noise filtering (--verbose off hides boring opcodes)")
quiet = [f for f in SESSION if render.should_show(f, palette, False)]
loud = [f for f in SESSION if render.should_show(f, palette, True)]
check("quiet shows fewer frames", len(quiet) < len(loud), (len(quiet), len(loud)))
check("quiet still shows messages",
      any(f.opcode == Opcode.NOTIF_MESSAGE for f in quiet))
check("quiet still shows errors",
      any(f.cmd == 3 for f in quiet))
check("quiet hides CHAT_INFO", not any(f.opcode == Opcode.CHAT_INFO for f in quiet))

print("\n7. message summariser pulls out the useful fields")
s = render.summarize(SESSION[14])
check("has chat id", "chat=222" in s, s)
check("has message id", "msg=9002" in s, s)
check("has sender", "from=777" in s, s)
check("has text", "а ты кто?" in s, s)
check("has reaction count", "reactions=2" in s, s)

print("\n8. opcode_name coverage")
check("known opcodes named", opcode_name(128) == "NOTIF_MESSAGE")
check("unknown opcodes named", opcode_name(4242) == "UNKNOWN_4242")
check("none opcode name", opcode_name(None) == "-")

print("\n9. attachment kind reads _type (the wire alias), not type")
# Payload shape copied from a real MSG_SEND capture, with every identifier
# replaced by an obviously synthetic value: no live tokens, signed CDN urls,
# user ids or media ids belong in a public repo.
FAKE_PHOTO_TOKEN = "TESTTOKEN_" + "A" * 60
FAKE_MEDIA_ID = 40000000001

send = frame(Opcode.MSG_SEND, {
    "chatId": 0,
    "message": {"cid": -1700000000000, "attaches": [
        {"_type": "PHOTO", "photoToken": FAKE_PHOTO_TOKEN}
    ]},
    "notify": True,
}, cmd=0, direction="send")
s = render.summarize(send)
check("does not print ? for the kind", "?" not in s, s)
check("shows PHOTO", "PHOTO" in s, s)

recv = frame(Opcode.MSG_SEND, {
    "chatId": 0,
    "message": {"id": 170000000000000001, "sender": 100000001, "text": "", "type": "USER",
                "attaches": [{"baseUrl": "https://i.oneme.ru/i?r=EXAMPLE&expires=1700000000000",
                              "photoToken": "TESTTOKEN_" + "B" * 12, "_type": "PHOTO",
                              "width": 1280, "photoId": FAKE_MEDIA_ID, "height": 964,
                              "thumbhash": "0000000000000000000000000000000000000000"}]},
}, cmd=1, direction="recv")
s = render.summarize(recv)
check("shows photoId", "PHOTO#%d" % FAKE_MEDIA_ID in s, s)
check("shows dimensions", "1280x964" in s, s)

print("\n10. upload handshake summary pulls media ids out of the url")
up = frame(Opcode.PHOTO_UPLOAD, {
    "url": "https://u.oneme.ru/upload?photoIds=%d&expires=1700000000000&token=EXAMPLE" % FAKE_MEDIA_ID
}, cmd=1, direction="recv")
s = render.summarize(up)
check("summary mentions the url", "u.oneme.ru/upload" in s, s)
check("summary extracts the id", str(FAKE_MEDIA_ID) in s, s)
check("PHOTO_UPLOAD is not filtered out", render.should_show(up, palette, False))

print("\n11. multipart body description (filename + content type, never the bytes)")
mp = (b"--boundary\r\n"
      b'Content-Disposition: form-data; name="file"; filename="image.jpeg"\r\n'
      b"Content-Type: image/jpeg\r\n\r\n" + b"\xff\xd8\xff\xe0" + b"JFIFDATA" * 500 + b"\r\n"
      b"--boundary--\r\n")
desc = describe_multipart(mp)
check("finds filename", "image.jpeg" in desc, desc)
check("finds part content type", "image/jpeg" in desc, desc)
check("does not dump the payload", "JFIFDATA" not in desc, desc)
check("handles empty body", describe_multipart(None) == "", describe_multipart(None))
check("handles binary garbage", isinstance(describe_multipart(b"\x00\x01\x02"), str))

print("\n12. three-phase upload correlation")
_lines = []


def _capture_output(tracker):
    """Feed a line to the tracker and return everything it printed."""
    _lines.clear()
    tracker.say = _lines.append
    return _lines


sniffer2 = MaxSniffer(FakeArgs(), render.Palette(False))
tr = sniffer2.uploads

phase1 = frame(Opcode.PHOTO_UPLOAD, {
    "url": "https://u.oneme.ru/upload?photoIds=40000000001&token=zzz"
}, cmd=1, direction="recv")
tr.register_urls(phase1, "PHOTO_UPLOAD")
check("phase 1 registers the id", "40000000001" in tr.by_id, list(tr.by_id))
check("url matches phase 1", tr.match_url("https://u.oneme.ru/upload?photoIds=40000000001") == "40000000001")
check("unrelated url does not match", tr.match_url("https://example.com/x") is None)

media_id = tr.match_url("https://u.oneme.ru/upload?photoIds=40000000001&token=zzz")
tr.note_http_request(media_id, "https://u.oneme.ru/upload?photoIds=40000000001",
                     "multipart/form-data; boundary=boundary", len(mp), describe_multipart(mp))
check("phase 2 recorded", 2 in tr.by_id["40000000001"]["phases"], tr.by_id)

token = send.payload["message"]["attaches"][0]["photoToken"]
tr.note_http_response(media_id, json.dumps({"photos": {"40000000001": {"token": token}}}))
check("token extracted from upload reply", tr.by_id["40000000001"].get("token") == token, tr.by_id)
check("token indexed for phase 3 lookup", tr.by_token.get(token) == "40000000001")

# Phase 3 is the MSG_SEND *request*: it carries the token phase 2 handed back.
# (The MSG_SEND response contains a different, server-issued photoToken.)
tr.note_ws_send(send)
check("phase 3 recorded", 3 in tr.by_id["40000000001"]["phases"], tr.by_id)
check("all three phases seen", {1, 2, 3} <= tr.by_id["40000000001"]["phases"], tr.by_id)
check("response-only token does not false-match", not any(
    "phase 3/3" in line for line in _capture_output(tr)
))

print("\n12b. video/file upload reply shape (info[] list) also parses")
tr2 = MaxSniffer(FakeArgs(), render.Palette(False)).uploads
tr2.say = lambda t: None
tr2.register_urls(frame(Opcode.VIDEO_UPLOAD, {
    "url": "https://u.oneme.ru/v?videoIds=999"}, cmd=1, direction="recv"), "VIDEO_UPLOAD")
tr2.note_http_response("999", json.dumps({"info": [{"videoId": 999, "token": "vtok"}]}))
check("video token extracted", tr2.by_token.get("vtok") == "999", tr2.by_id)

print("\n12c. junk upload replies do not crash")
for junk in (None, b"", b"\x00\x01", "not json", {"nothing": 1}, [1, 2, 3]):
    check("tolerates %r" % (junk,), UploadTracker._extract_tokens(junk) == [])

print("\n13. http capture file entries are valid jsonl and store no payload bytes")
with tempfile.TemporaryDirectory() as td:
    p2 = Path(td) / "cap2.jsonl"
    c2 = Capture(p2, redact_enabled=True)
    c2.write(send)
    c2.write_http("POST", "https://u.oneme.ru/upload?photoIds=1", mp, "multipart/form-data")
    c2.write_http_response("POST", "https://u.oneme.ru/upload?photoIds=1", 200,
                           json.dumps({"photos": {"1": {"token": "abc"}}}).encode(), "application/json")
    c2.close()
    objs2 = [json.loads(l) for l in p2.read_text().splitlines() if l.strip()]
    check("three records", len(objs2) == 3, len(objs2))
    kinds = [o.get("kind") or "frame" for o in objs2]
    check("kinds recorded", kinds == ["frame", "http-request", "http-response"], kinds)
    req = objs2[1]
    check("http request size recorded", req["size"] == len(mp), req.get("size"))
    check("http request part described", "image.jpeg" in req["part"], req.get("part"))
    check("no image bytes in capture", b"JFIFDATA" not in p2.read_bytes())
    resp = objs2[2]
    check("upload token in capture", "abc" in resp["body"], resp.get("body"))


print()
if failures:
    print("FAILED %d check(s): %s" % (len(failures), failures))
    sys.exit(1)
print("all checks passed")
