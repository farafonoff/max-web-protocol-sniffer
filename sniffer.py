#!/usr/bin/env python3
"""sniffer - open MAX in a real Chrome, let you log in, decode the wire traffic.

Launches Google Chrome with a persistent profile, opens web.max.ru, and waits
for you to authenticate by hand. Every websocket frame the page sends or
receives is decoded and printed, and appended to a JSONL capture file. The
page's JavaScript bundles are saved to disk at the same time so you can grep
them for opcode numbers, request paths, or field names.

    ./run.sh                 # launch, log in, sniff
    python sniffer.py --full # print whole payloads, not previews
    python sniffer.py -v      # every frame, including boring ones
"""

import argparse
import asyncio
import base64
import json
import re
import signal
import sys
import time
from collections import Counter
from pathlib import Path

from playwright.async_api import async_playwright

import frames
import render
from render import human_size
from opcodes import OPCODE_NAMES, Opcode, opcode_name

BASE = Path(__file__).resolve().parent
PROFILE_DIR = BASE / "chrome_profile_max"
CAPTURE_DIR = BASE / "captures"
JS_DIR = BASE / "js"

DEFAULT_URL = "https://web.max.ru/"
CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# Websocket URLs worth decoding. Everything is captured to the capture file
# regardless; this only controls what gets printed.
MAX_URL_HINTS = ("oneme.ru", "max.ru", "maxmail.ru")

# Opcode that means "you are logged in and the session is live".
LOGIN_OPCODES = {Opcode.LOGIN, Opcode.LOGIN2, Opcode.WEB_APP_INIT_DATA}

# Opcodes that hand back a presigned upload url. The bytes go over HTTP after.
UPLOAD_OPCODES = {
    Opcode.PHOTO_UPLOAD,
    Opcode.VIDEO_UPLOAD,
    Opcode.FILE_UPLOAD,
    Opcode.STICKER_UPLOAD,
}

# How much of a multipart body to scan for its part headers.
MULTIPART_SCAN = 8192


def pick_devtools_port(preferred):
    """Find a free port for the CDP listener.

    A previous run that was SIGKILLed can leave Chrome alive holding both the
    profile and the debug port (Playwright's node driver survives and keeps
    respawning it). Reusing that port just hangs the launch, so probe for a
    free one instead.
    """
    import socket

    for offset in range(0, 50):
        candidate = preferred + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    return preferred


def profile_locked():
    """Is another Chrome already using our profile directory?

    Chrome's SingletonLock makes a second launch reuse the first window instead
    of starting fresh, which means a stale instance silently owns the session.
    """
    return (PROFILE_DIR / "SingletonLock").exists() and _stale_chrome_running()


def _stale_chrome_running():
    try:
        import subprocess

        out = subprocess.run(
            ["pgrep", "-f", "chrome_profile_max"],
            capture_output=True, text=True, timeout=5,
        )
        return bool(out.stdout.strip())
    except Exception:
        return False


def describe_multipart(body):
    """Pull `name="file"; filename="image.jpeg"` out of a multipart body.

    Only the first few KB are scanned, and the payload itself is never printed:
    you want to know it sent a 4.2MB JPEG, not to see the JPEG.
    """
    if not body:
        return ""
    head = body[:MULTIPART_SCAN]
    try:
        text = head.decode("utf-8", "replace")
    except Exception:
        return ""
    filename = ""
    part_type = ""
    for line in text.split("\n"):
        line = line.strip("\r")
        if line.lower().startswith("content-disposition"):
            match = re.search(r'filename="([^"]*)"', line)
            if match:
                filename = match.group(1)
            else:
                match = re.search(r'name="([^"]*)"', line)
                if match:
                    filename = "field:%s" % match.group(1)
        elif line.lower().startswith("content-type") and "multipart" not in line.lower():
            part_type = line.split(":", 1)[-1].strip()
    bits = []
    if filename:
        bits.append(filename)
    if part_type:
        bits.append(part_type)
    return " ".join(bits)


def now_stamp():
    t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t)) + ".%03d" % ((t % 1) * 1000)


def is_max_socket(url):
    if not url:
        return False
    low = url.lower()
    return any(h in low for h in MAX_URL_HINTS) or low.startswith("wss://")


class Capture:
    """Appends every decoded frame to a JSONL file, one object per line."""

    def __init__(self, path, redact_enabled):
        self.path = path
        self.redact_enabled = redact_enabled
        self.fh = open(path, "w", encoding="utf-8")
        self.count = 0

    def write(self, frame):
        obj = frame.to_dict(redact=render.redact if self.redact_enabled else None)
        # The verbatim frame still contains the credentials we just redacted
        # out of the payload (an SMS code sits in the raw JSON too), so raw
        # bytes are only persisted in --no-redact mode.
        obj["raw_hex"] = None
        obj["raw_truncated"] = None
        if not self.redact_enabled:
            if isinstance(frame.raw, (bytes, bytearray)):
                obj["raw_hex"] = frame.raw[:512].hex()
            elif isinstance(frame.raw, str) and len(frame.raw) > 1200:
                obj["raw_truncated"] = frame.raw[:1200]
        self._emit(obj)

    def write_http(self, method, url, body, content_type):
        """Record the upload POST. The body is summarised, never stored: it is
        the user's photo or video, and it is megabytes."""
        self._emit({
            "ts": now_stamp(),
            "kind": "http-request",
            "method": method,
            "url": url,
            "content_type": content_type,
            "size": len(body),
            "part": describe_multipart(body),
        })

    def write_http_response(self, method, url, status, body, content_type):
        self._emit({
            "ts": now_stamp(),
            "kind": "http-response",
            "method": method,
            "url": url,
            "status": status,
            "content_type": content_type,
            "body": body.decode("utf-8", "replace")[:2000]
            if isinstance(body, (bytes, bytearray))
            else body,
        })

    def _emit(self, obj):
        self.count += 1
        self.fh.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()


class JsCollector:
    """Saves the web client's JavaScript bundles for offline grepping."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.saved = 0
        self.seen = 0
        if enabled:
            JS_DIR.mkdir(exist_ok=True)

    async def handle(self, response):
        if not self.enabled:
            return
        url = response.url
        ctype = ""
        try:
            ctype = (response.headers or {}).get("content-type", "")
        except Exception:
            pass
        is_js = (
            re.search(r"\.js(\?|$)", url)
            or "javascript" in ctype
            or url.endswith("/chunk")
        )
        if not is_js:
            return
        self.seen += 1
        try:
            body = await response.body()
        except Exception:
            return
        if not body:
            return
        name = self._name_for(url)
        try:
            (JS_DIR / name).write_bytes(body)
        except OSError:
            return
        self.saved += 1

    @staticmethod
    def _name_for(url):
        clean = re.sub(r"^https?://", "", url)
        clean = re.sub(r"[^A-Za-z0-9._-]+", "_", clean)
        return clean[:150]


class UploadTracker:
    """Follows a media upload across all three of its phases.

    Media does not travel over the websocket. The protocol is:

      phase 1  WS   PHOTO_UPLOAD (80)     -> {"url": "...&photoIds=46755532157"}
      phase 2  HTTP POST multipart/form-data to that url
                                            -> {"photos": {"46755532157": {"token": "..."}}}
      phase 3  WS   MSG_SEND (64)         -> attaches[].photoToken == that token

    Phase 2 is a plain HTTPS request to a presigned url, so a websocket-only
    sniffer shows you phase 3 and leaves you wondering where photoToken came
    from. This matches the three back up and labels them.
    """

    def __init__(self, say, palette):
        self.say = say
        self.palette = palette
        self.by_id = {}       # media id -> {"url", "token", "phases": set()}
        self.by_token = {}    # token -> media id
        self.pending = []     # attaches seen before their token was known
        self.count = 0

    def _record(self, media_id, **fields):
        entry = self.by_id.setdefault(str(media_id), {"phases": set()})
        entry.update({k: v for k, v in fields.items() if v is not None})
        return entry

    def register_urls(self, frame, opcode_name_str):
        """Phase 1: a *_UPLOAD response handed us a presigned url."""
        payload = frame.payload if isinstance(frame.payload, dict) else {}
        url = payload.get("url")
        if not url:
            return None
        ids = render._query_ids(url) or [
            str(payload[k]) for k in ("photoId", "videoId", "fileId") if payload.get(k)
        ]
        self.count += 1
        if not ids:
            self.say("  %s %s" % (self.palette.grey("phase 1/3"), self.palette.grey("url has no media id")))
            return url
        for media_id in ids:
            self._record(media_id, url=url)["phases"].add(1)
            self.by_token.setdefault(media_id, media_id)
        self.say("  %s %s  %s  %s" % (
            self.palette.cyan("phase 1/3"),
            self.palette.bold(opcode_name_str),
            self.palette.grey("ids=" + ",".join(ids[:6])),
            self.palette.grey("-> presigned url"),
        ))
        return url

    def match_url(self, url):
        """Phase 2: find which media id this HTTP request belongs to."""
        if not url:
            return None
        for media_id, entry in self.by_id.items():
            if entry.get("phases") and 2 in entry["phases"]:
                continue
            if media_id in url or entry.get("url") == url:
                return media_id
        return None

    def note_http_request(self, media_id, url, content_type, size, part_info):
        entry = self._record(media_id, url=url)
        entry["phases"].add(2)
        bits = []
        if content_type:
            bits.append(content_type.split(";")[0])
        if size is not None:
            bits.append(human_size(size))
        bits.append(part_info or "")
        self.say("  %s %s  %s  %s" % (
            self.palette.cyan("phase 2/3"),
            self.palette.bold("HTTP POST"),
            self.palette.grey(" ".join(b for b in bits if b)),
            self.palette.grey("id=%s" % media_id),
        ))

    def note_http_response(self, media_id, body):
        """Phase 2b: pull the photoToken (or video/file token) out of the reply."""
        entry = self._record(media_id)
        entry["phases"].add(2)
        tokens = self._extract_tokens(body)
        for token, media_id_from_body in tokens:
            target = str(media_id_from_body or media_id)
            self._record(target, token=token)["phases"].add(2)
            self.by_token[token] = target
        if tokens:
            summary = ", ".join(
                "%s=%s" % (mid, tok[:16] + "…") for tok, mid in tokens[:4]
            )
            self.say("  %s %s  %s" % (
                self.palette.green("phase 2/3 done"),
                self.palette.grey("token(s):"),
                self.palette.bold(summary),
            ))
            # A MSG_SEND can overtake the upload reply on the wire, so retry any
            # attach we could not match when the token was still unknown.
            self._drain_pending()

    def _match_attach(self, attach, frame_opcode):
        token = attach.get("photoToken") or attach.get("token")
        if not token:
            return None
        media_id = self.by_token.get(token)
        if media_id is None:
            return None
        entry = self.by_id.setdefault(str(media_id), {"phases": set()})
        entry["phases"].add(3)
        kind = attach.get("_type") or attach.get("type") or "?"
        self.say("  %s %s  %s  %s" % (
            self.palette.magenta("phase 3/3"),
            self.palette.bold("%s %s" % (opcode_name(frame_opcode), kind)),
            self.palette.grey("id=%s" % media_id),
            self.palette.grey("token matches phase 2"),
        ))
        return media_id

    def _drain_pending(self):
        if not self.pending:
            return
        still_pending = []
        for frame_opcode, attach in self.pending:
            if self._match_attach(attach, frame_opcode) is None:
                still_pending.append((frame_opcode, attach))
        self.pending = still_pending

    @staticmethod
    def _extract_tokens(body):
        """Find {token: id} pairs in an upload reply.

        pymax reads `{"photos": {"<photoId>": {"token": "..."}}}` for photos and
        `{"info": [{"videoId":…, "token":…}]}` for video/file, so handle both.
        """
        found = []
        if isinstance(body, (bytes, bytearray)):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                return found
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return found
        if not isinstance(body, dict):
            return found

        photos = body.get("photos")
        if isinstance(photos, dict):
            for media_id, item in photos.items():
                if isinstance(item, dict) and item.get("token"):
                    found.append((item["token"], media_id))

        info = body.get("info")
        if isinstance(info, list):
            for item in info:
                if not isinstance(item, dict):
                    continue
                token = item.get("token")
                media_id = item.get("videoId") or item.get("fileId")
                if token:
                    found.append((token, media_id))

        if not found:
            token = body.get("token")
            if token:
                found.append((token, body.get("photoId") or body.get("videoId")))
        return found

    def note_ws_send(self, frame):
        """Phase 3: a MSG_SEND carrying a token we saw come back in phase 2."""
        payload = frame.payload if isinstance(frame.payload, dict) else {}
        msg = payload.get("message") if isinstance(payload.get("message"), dict) else payload
        attaches = msg.get("attaches") if isinstance(msg, dict) else None
        if not isinstance(attaches, list):
            return
        for attach in attaches:
            if not isinstance(attach, dict):
                continue
            if self._match_attach(attach, frame.opcode) is None:
                self.pending.append((frame.opcode, attach))

    def report(self):
        if not self.by_id:
            return
        self.say("media uploads    %d seen, %d completed all 3 phases" % (
            self.count,
            sum(1 for e in self.by_id.values() if {1, 2, 3} <= e["phases"]),
        ))


class MaxSniffer:
    # Identical (method, url, size) inside this window counts as one request.
    REQUEST_DEDUPE_WINDOW = 2.0

    def __init__(self, args, palette):
        self.args = args
        self.palette = palette
        self.capture = None
        self.js = JsCollector(not args.no_js)
        self.uploads = UploadTracker(self.say, palette)
        self.http_requests = {}   # playwright Request -> {"media_id", ...}
        self._recent_requests = {}
        self.http_count = 0
        self.context = None
        self._intercept_armed = False
        self.sockets = {}          # playwright WebSocket -> {"url": ...}
        self.decoders = {}         # (playwright WebSocket, direction) -> BinaryStreamDecoder
        self.opcode_counts = Counter()
        self.direction_counts = Counter()
        self.printed = 0
        self.seen_max_socket = False
        self.authenticated = False
        self.started = time.time()
        self.pages = []

    # ---------- console helpers ----------

    def say(self, text):
        print("%s %s" % (self.palette.grey(now_stamp()), text), flush=True)

    def banner(self, text):
        print("", flush=True)
        print(render.format_banner(text, self.palette), flush=True)

    def emit(self, frame, frame_note=None):
        if frame_note:
            frame.note = frame_note
        self.capture.write(frame)

        if frame.opcode is not None:
            self.opcode_counts[frame.opcode] += 1
        self.direction_counts[frame.direction] += 1

        if not render.should_show(frame, self.palette, self.args.verbose):
            return
        if frame.direction == "send" and not self.args.show_sends:
            return
        self.printed += 1
        print(render.format_frame(frame, self.palette, full=self.args.full), flush=True)

    # ---------- protocol events ----------

    def maybe_authenticated(self, frame):
        if self.authenticated:
            return
        if frame.opcode in LOGIN_OPCODES and frame.direction == "recv":
            self.authenticated = True
            self.banner(self.palette.green("authenticated - session is live, now use MAX normally"))

    # ---------- http (this is where media bytes actually go) ----------

    async def arm_interception(self):
        """Turn on Playwright request interception, but only once we're connected.

        Playwright only populates `request.post_data_buffer` for requests it is
        actively intercepting: with no routes registered, the POST body of a
        FormData/blob upload comes back as None and you cannot see the filename
        or the size. Registering a catch-all route fixes that, but Playwright
        documents that routing disables the HTTP cache, so we arm it *after*
        the page has loaded and the MAX socket is open. The initial page load
        therefore still runs un-intercepted and cached.

        This also closes the race in the other direction: the upload POST is
        issued seconds after the socket opens, long after we are armed.
        """
        if self.args.no_intercept or self._intercept_armed or self.context is None:
            return
        self._intercept_armed = True

        async def passthrough(route):
            try:
                await route.continue_()
            except Exception:
                pass

        try:
            await self.context.route("**/*", passthrough)
            self.say(self.palette.grey(
                "request interception armed (upload bodies will be visible)"
            ))
        except Exception as err:
            self.say(self.palette.yellow(
                "could not arm request interception: %s" % err
            ))

    def _upload_candidate(self, request):
        """Is this HTTP request worth printing?

        Media uploads never touch the websocket framing, so without this the
        sniffer appears to skip straight from PHOTO_UPLOAD to MSG_SEND.
        """
        method = (request.method or "").upper()
        if method not in ("POST", "PUT", "PATCH"):
            return False
        headers = request.headers or {}
        ctype = headers.get("content-type", "")
        url = (request.url or "").lower()
        if "multipart/form-data" in ctype:
            return True
        if self.uploads.match_url(request.url):
            return True
        if self.args.http:
            return True
        return any(k in url for k in ("upload", "photo", "video", "sticker", "/file"))

    def _dedupe_key(self, request, body):
        return (
            (request.method or "").upper(),
            request.url or "",
            len(body) if body else None,
        )

    def _is_duplicate_request(self, key):
        """Arming interception mid-session makes Chrome emit some requests twice.

        Playwright surfaces both the Fetch-paused and the network-level event,
        which would print the same upload POST twice and double-count it. Drop
        an identical (method, url, size) seen in the last couple of seconds.
        """
        now = time.monotonic()
        previous = self._recent_requests.get(key)
        if previous is not None and (now - previous) < self.REQUEST_DEDUPE_WINDOW:
            return True
        self._recent_requests[key] = now
        if len(self._recent_requests) > 64:
            cutoff = now - self.REQUEST_DEDUPE_WINDOW
            self._recent_requests = {
                k: v for k, v in self._recent_requests.items() if v >= cutoff
            }
        return False

    def on_request(self, request):
        body = None
        try:
            body = request.post_data_buffer
        except Exception:
            body = None

        if self._is_duplicate_request(self._dedupe_key(request, body)):
            return
        if not self._upload_candidate(request):
            return

        headers = request.headers or {}
        ctype = headers.get("content-type", "")

        media_id = self.uploads.match_url(request.url)
        part_info = describe_multipart(body)
        self.http_count += 1
        self.http_requests[request] = {
            "media_id": media_id,
            "content_type": ctype,
            "size": len(body) if body else None,
        }

        if media_id is not None:
            self.uploads.note_http_request(media_id, request.url, ctype,
                                           len(body) if body else None, part_info)
        else:
            print(render.format_http(
                request.method, request.url, self.palette,
                note=" ".join(x for x in (part_info,) if x) or "body not captured",
                req_size=len(body) if body else None,
            ), flush=True)

        self.capture.write_http(request.method, request.url, body, ctype)

    def on_response(self, response):
        request = response.request
        # Pop, do not get: a response can surface more than once, and holding
        # every Request object forever would leak for the life of the session.
        info = self.http_requests.pop(request, None)
        if info is None:
            return
        asyncio.ensure_future(self._finish_response(response, info))

    async def _finish_response(self, response, info):
        media_id = info.get("media_id")
        ctype = ""
        try:
            ctype = (response.headers or {}).get("content-type", "")
        except Exception:
            pass

        body = None
        if "json" in ctype or not ctype:
            try:
                body = await response.body()
            except Exception:
                body = None

        print(render.format_http(
            response.request.method, response.url, self.palette,
            status=response.status, body=body, full=self.args.full,
            note=("media id=%s" % media_id) if media_id else None,
        ), flush=True)

        if media_id is not None:
            self.uploads.note_http_response(media_id, body)

        self.capture.write_http_response(
            response.request.method, response.url, response.status, body, ctype
        )

    def handle_decoded(self, frame):
        op = frame.opcode
        if op in UPLOAD_OPCODES and frame.direction == "recv":
            self.uploads.register_urls(frame, opcode_name(op))
        elif op == Opcode.MSG_SEND:
            self.uploads.note_ws_send(frame)

        self.emit(frame)
        self.maybe_authenticated(frame)

    def on_text(self, ws, payload, direction):
        text = payload if isinstance(payload, str) else payload.decode("utf-8", "replace")
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            self.handle_decoded(
                frames.decode_json_frame(
                    text, direction, ws_url=self.sockets.get(ws, {}).get("url")
                )
            )
            return
        # Not JSON: could be the binary framing base64'd into a text frame, or
        # something unrelated. Try the binary path before giving up.
        try:
            blob = base64.b64decode(text, validate=True)
        except Exception:
            blob = text.encode("utf-8", "replace")
        produced = self.decoders[(ws, direction)].feed(blob)
        if produced:
            for frame in produced:
                self.handle_decoded(frame)
        else:
            frame = frames.MaxFrame(None, None, None, None, 0, None, text, "opaque", direction)
            frame.note = "unrecognised frame (not json, not max binary)"
            frame.ws_url = self.sockets.get(ws, {}).get("url")
            self.handle_decoded(frame)

    def on_binary(self, ws, payload, direction):
        blob = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode()
        produced = self.decoders[ws].feed(blob)
        for frame in produced:
            self.handle_decoded(frame)

    # ---------- playwright wiring ----------

    def attach(self, page):
        if page in self.pages:
            return
        self.pages.append(page)

        def on_websocket(ws):
            url = ws.url
            self.sockets[ws] = {"url": url}
            self.decoders[(ws, "recv")] = frames.BinaryStreamDecoder("recv", url)
            self.decoders[(ws, "send")] = frames.BinaryStreamDecoder("send", url)
            if is_max_socket(url):
                self.seen_max_socket = True
                self.say(
                    "%s %s"
                    % (self.palette.green("socket open"), self.palette.bold(url))
                )
            else:
                self.say(
                    "%s %s %s"
                    % (
                        self.palette.grey("socket open (non-max)"),
                        self.palette.grey(url),
                        self.palette.grey("- still captured to file"),
                    )
                )

            ws.on("framesent", lambda payload: self._route(ws, payload, "send"))
            ws.on("framereceived", lambda payload: self._route(ws, payload, "recv"))
            ws.on("socketerror", lambda err: self.say(
                "%s %s" % (self.palette.red("socket error:"), err)
            ))
            ws.on("close", lambda: self.say(
                "%s %s"
                % (
                    self.palette.yellow("socket closed"),
                    self.palette.grey(
                        "%s (%d bytes buffered)"
                        % (url, self.decoders[(ws, "recv")].pending)
                    ),
                )
            ))

        page.on("websocket", on_websocket)
        page.on("response", lambda r: asyncio.ensure_future(self.js.handle(r)))
        page.on("request", self.on_request)
        page.on("response", self.on_response)

    def _route(self, ws, payload, direction):
        decoder = self.decoders[(ws, direction)]
        if isinstance(payload, (bytes, bytearray)):
            for frame in decoder.feed(payload):
                self.handle_decoded(frame)
            return
        self.on_text(ws, payload, direction)

    # ---------- run ----------

    async def run(self):
        CAPTURE_DIR.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        capture_path = CAPTURE_DIR / ("max_%s.jsonl" % stamp)
        self.capture = Capture(capture_path, not self.args.no_redact)

        async with async_playwright() as pw:
            port = pick_devtools_port(self.args.devtools_port)
            if port != self.args.devtools_port:
                self.say(self.palette.yellow(
                    "devtools port %d is in use, using %d instead"
                    % (self.args.devtools_port, port)
                ))
            self.banner(self.palette.bold("max-reverse sniffer"))
            self.say("chrome     %s" % CHROME_PATH)
            self.say("profile    %s" % PROFILE_DIR)
            self.say("url        %s" % self.args.url)
            self.say("devtools   http://localhost:%d" % port)
            self.say("capture    %s%s" % (
                capture_path,
                self.palette.grey("  (credentials redacted)" if not self.args.no_redact else "  (RAW, credentials included)"),
            ))
            self.say("js bundles %s" % (JS_DIR if self.js.enabled else self.palette.grey("disabled")))
            if profile_locked():
                self.say(self.palette.yellow(
                    "note: another Chrome still holds this profile; "
                    "quit it first or run with --url in a fresh window"
                ))
            print("", flush=True)

            try:
                context = await pw.chromium.launch_persistent_context(
                    user_data_dir=str(PROFILE_DIR),
                    channel="chrome",
                    headless=False,
                    args=[
                        "--remote-debugging-port=%d" % port,
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                    timeout=45000,
                )
            except Exception as err:
                print("", flush=True)
                print("%s could not start Chrome: %s" % (self.palette.red("error:"), err),
                      file=sys.stderr)
                print("If a previous run was force-killed, quit the stray Chrome "
                      "window (it keeps the profile locked) and try again.",
                      file=sys.stderr)
                self.capture.close()
                raise
            self.context = context
            for page in context.pages:
                self.attach(page)
            context.on("page", lambda p: self.attach(p))

            self.banner(self.palette.yellow("log into MAX in the Chrome window"))
            self.say(self.palette.grey("sniffing starts on navigation; Ctrl-C to stop"))

            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, stop.set)
                except NotImplementedError:
                    pass

            page = context.pages[0] if context.pages else await context.new_page()
            await page.goto(self.args.url, wait_until="domcontentloaded")
            self.say(self.palette.grey("navigated, capturing from here on"))

            # Arm interception now: the initial page load ran cached, and any
            # upload happens later (after login), so there is no race.
            await self.arm_interception()

            try:
                await self._supervise(context, stop)
            finally:
                self.report(capture_path)
                try:
                    await context.close()
                except Exception:
                    pass

    async def _supervise(self, context, stop):
        """Idle until Ctrl-C, nudging the user if we never see MAX traffic."""
        warned_auth = False
        warned_socket = False
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=2)
                return
            except asyncio.TimeoutError:
                pass
            pages = context.pages
            if pages and pages[0].is_closed():
                self.say(self.palette.yellow("browser window was closed"))
                return
            elapsed = time.time() - self.started
            if not warned_socket and elapsed > 20 and not self.seen_max_socket:
                warned_socket = True
                self.say(self.palette.yellow(
                    "no MAX socket seen yet - if you are logged in, reload the page (cmd-R)"
                ))
            if not warned_auth and elapsed > 60 and not self.authenticated:
                warned_auth = True
                self.say(self.palette.yellow(
                    "still not authenticated - log in, or the socket predates this sniffer"
                ))

    def report(self, capture_path):
        self.banner(self.palette.bold("summary"))
        self.say("frames captured  %d  (printed %d)" % (self.capture.count, self.printed))
        self.say("directions       sent=%d recv=%d" % (
            self.direction_counts["send"], self.direction_counts["recv"]
        ))
        if self.js.enabled:
            self.say("js bundles       %d saved to %s" % (self.js.saved, JS_DIR))
        self.say("http requests    %d printed" % self.http_count)
        self.uploads.report()
        self.say("capture file     %s" % capture_path)

        if self.opcode_counts:
            self.say("")
            self.say("%s" % self.palette.bold("top opcodes"))
            for op, n in self.opcode_counts.most_common(15):
                self.say("  %-5d %-34s %d" % (op, opcode_name(op), n))

        unknown = [op for op in self.opcode_counts if op not in OPCODE_NAMES]
        if unknown:
            self.say("")
            self.say("%s %s" % (
                self.palette.yellow("opcodes missing from opcodes.py (add them!):"),
                ", ".join(str(u) for u in sorted(unknown)),
            ))


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="sniffer",
        description="Open MAX in Chrome, log in by hand, decode the websocket traffic.",
    )
    p.add_argument("--url", default=DEFAULT_URL, help="page to open (default: %(default)s)")
    p.add_argument("-v", "--verbose", action="store_true", help="print every frame, not just interesting ones")
    p.add_argument("--full", action="store_true", help="print payloads in full instead of truncating")
    p.add_argument("--no-sends", dest="show_sends", action="store_false", help="only print inbound frames")
    p.add_argument("--no-redact", action="store_true", help="write credentials to the capture file too")
    p.add_argument("--no-js", action="store_true", help="do not save javascript bundles")
    p.add_argument("--no-intercept", action="store_true",
                   help="do not intercept HTTP requests (keeps the browser cache warm, "
                        "but upload filenames and sizes will not be visible)")
    p.add_argument("--http", action="store_true",
                   help="print every POST/PUT, not just uploads (noisy)")
    p.add_argument("--devtools-port", type=int, default=9333, help="expose CDP for manual devtools (default: %(default)s)")
    p.add_argument("--devtools", action="store_true", help="print the devtools attach hint on start")
    p.set_defaults(show_sends=True, http=False, no_intercept=False)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    palette = render.Palette(render.color_enabled())
    sniffer = MaxSniffer(args, palette)

    if not Path(CHROME_PATH).exists():
        print("Chrome not found at %s" % CHROME_PATH, file=sys.stderr)
        print("Change CHROME_PATH at the top of sniffer.py.", file=sys.stderr)
        return 1

    if args.devtools:
        print("after Chrome starts, attach devtools to http://localhost:%d" % args.devtools_port)

    try:
        asyncio.run(sniffer.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
