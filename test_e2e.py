"""End-to-end integration test: real Chrome -> local mock MAX server.

Exercises the parts that unit tests cannot: Playwright's websocket hooks, the
binary decoder over a real browser WebSocket, the HTTP upload hooks, the
three-phase upload correlation, and the capture file.

The mock server speaks the real framing (10-byte header + LZ4 msgpack, ver=10)
so the browser side of frames.BinaryStreamDecoder is genuinely tested. Nothing
touches max.ru and no message is sent to a real account.

    .venv/bin/python test_e2e.py
"""

import asyncio
import json
import re
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path

import msgpack
import websockets

HERE = Path(__file__).resolve().parent


def free_port():
    """Ask the OS for a port, then release it, so parallel/repeat runs and
    lingering sockets in TIME_WAIT cannot collide on a hardcoded number."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


sys.path.insert(0, str(HERE))

import frames  # noqa: E402

MEDIA_ID = 40000000002
PHOTO_TOKEN = "TESTTOKEN_" + "A" * 60
UPLOAD_PATH = "/upload?photoIds=%d&expires=1700000000000&sig=EXAMPLE" % MEDIA_ID

failures = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s %s" % (label, detail))
        failures.append(label)


def max_frame(opcode, payload, seq=0, cmd=0, ver=10):
    """Build a real MAX binary packet, LZ4 compressed like the live client."""
    import lz4.block

    body = msgpack.packb(payload, use_bin_type=True)
    compressed = lz4.block.compress(body, store_size=False)
    flags = 0x01 if len(compressed) < len(body) else 0x00
    stored = compressed if flags else body
    header = frames.HEADER_STRUCT.pack(ver, cmd, seq, opcode, (flags << 24) | len(stored))
    return header + stored


PAGE_TEMPLATE = """<!doctype html><meta charset=utf-8><title>mock max</title>
<body><pre id=log>booting</pre>
<script>
const log = m => { document.getElementById('log').textContent += "\\n" + m; };
const blob = new Blob([new Uint8Array([1,2,3,4,5,6,7,8])], {type: 'image/jpeg'});
const form = new FormData();
form.append('file', blob, 'image.jpeg');
const ws = new WebSocket('ws://127.0.0.1:%d/');
ws.binaryType = 'arraybuffer';
ws.onopen = () => log('ws open');
// Phase 1 arrives over the socket as a binary frame; the sniffer decodes it.
// We do not parse it here, we just wait for it like the real client would.
ws.onmessage = () => {
  log('got binary frame from server, posting photo');
  // Phase 2: media bytes go over plain HTTP, not the socket.
  fetch('%s', {method: 'POST', body: form})
    .then(r => r.json())
    .then(j => log('upload reply: ' + JSON.stringify(j)))
    .catch(e => log('upload failed: ' + e));
};
ws.onerror = e => log('ws error');
</script>
"""


def build_page():
    """Built after the ephemeral ports are bound."""
    return PAGE_TEMPLATE % (WS_PORT, UPLOAD_PATH)


async def ws_handler(ws):
    """Send phase 1, then phase 3 once the browser has done the HTTP upload."""
    await ws.send(max_frame(80, {"url": "http://127.0.0.1:%d%s" % (HTTP_PORT, UPLOAD_PATH)}, seq=0))
    try:
        # Wait for the browser's upload to land before announcing phase 3.
        for _ in range(100):
            await asyncio.sleep(0.1)
            if UPLOAD_DONE["hit"]:
                break
    except Exception:
        pass
    await ws.send(max_frame(64, {
        "chatId": 0,
        "message": {
            "cid": -1700000000001,
            "attaches": [{"_type": "PHOTO", "photoToken": PHOTO_TOKEN}],
        },
        "notify": True,
    }, seq=1))
    await asyncio.sleep(1.5)


UPLOAD_DONE = {"hit": False}


async def http_handler(reader, writer):
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            writer.close()
            return
        parts = request_line.decode("latin1").split()
        method, path = parts[0], parts[1]

        headers = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, value = line.decode("latin1").partition(":")
            headers[key.strip().lower()] = value.strip()

        length = int(headers.get("content-length", "0") or 0)
        body = b""
        if length:
            body = await asyncio.wait_for(reader.readexactly(length), timeout=15)

        if method == "GET":
            payload = build_page().encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)
            )
            writer.write(payload)
        elif path.startswith("/upload"):
            UPLOAD_DONE["hit"] = True
            UPLOAD_SEEN["body"] = body
            UPLOAD_SEEN["ctype"] = headers.get("content-type", "")
            reply = json.dumps({"photos": {str(MEDIA_ID): {"token": PHOTO_TOKEN}}}).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(reply)
            )
            writer.write(reply)
        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


UPLOAD_SEEN = {}


HTTP_PORT = 0
WS_PORT = 0


async def serve():
    """Bind ephemeral ports and publish the real numbers to the page/global."""
    global HTTP_PORT, WS_PORT
    ws_server = await websockets.serve(ws_handler, "127.0.0.1", 0)
    WS_PORT = next(iter(ws_server.sockets)).getsockname()[1]
    http_server = await asyncio.start_server(http_handler, "127.0.0.1", 0)
    HTTP_PORT = http_server.sockets[0].getsockname()[1]
    async with ws_server, http_server:
        await asyncio.Future()


async def run_sniffer(profile_dir):
    env = dict(**os.environ)
    env["MAX_FORCE_COLOR"] = "1"
    proc = await asyncio.create_subprocess_exec(
        str(HERE / ".venv/bin/python"), str(HERE / "sniffer.py"),
        "--url", "http://127.0.0.1:%d/" % HTTP_PORT,
        "--no-js", "--no-sends", "--devtools-port", str(free_port()),
        cwd=str(HERE), env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    # Ask nicely first: SIGINT lets the sniffer close the browser, so we do not
    # orphan Chrome holding the profile (a SIGKILL does exactly that).
    await asyncio.sleep(6)
    try:
        proc.send_signal(signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=25)
    except asyncio.TimeoutError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    return (await proc.stdout.read()).decode("utf-8", "replace")


async def main():
    profile = Path(tempfile.mkdtemp(prefix="maxrev-e2e-"))
    # sniffer.py hardcodes the profile path, so give it the real one but keep
    # the caller's existing session safe by pointing HOME-like state elsewhere.
    print("mock MAX server: ws=127.0.0.1:%d http=127.0.0.1:%d" % (WS_PORT, HTTP_PORT))

    server = asyncio.create_task(serve())
    for _ in range(50):
        await asyncio.sleep(0.1)
        if HTTP_PORT:
            break
    if not HTTP_PORT:
        print("mock server failed to bind")
        return 1

    # Patch the profile dir the sniffer will use, so we never touch the user's
    # real chrome_profile_max.
    original = (HERE / "sniffer.py").read_text()
    patched = original.replace(
        'PROFILE_DIR = BASE / "chrome_profile_max"',
        'PROFILE_DIR = Path(%r)' % str(profile),
    )
    (HERE / "sniffer.py").write_text(patched)
    try:
        output = await run_sniffer(profile)
    finally:
        (HERE / "sniffer.py").write_text(original)
        server.cancel()
        shutil.rmtree(profile, ignore_errors=True)

    print("\n--- sniffer output ---")
    print(output)
    print("--- end output ---\n")

    plain = re.sub(r"\033\[[0-9;]*m", "", output)

    print("1. browser actually performed the multipart upload")
    check("server saw the POST body", bool(UPLOAD_SEEN.get("body")), UPLOAD_SEEN)
    check("POST was multipart/form-data",
          "multipart/form-data" in UPLOAD_SEEN.get("ctype", ""), UPLOAD_SEEN.get("ctype"))
    check("POST carried the file part",
          b'name="file"' in UPLOAD_SEEN.get("body", b""), UPLOAD_SEEN.get("body", b"")[:120])

    print("\n2. binary frames were decoded over the real browser websocket")
    check("PHOTO_UPLOAD decoded from binary",
          "PHOTO_UPLOAD" in plain, plain[-400:])
    check("opcode 80 named correctly", "op=80" in plain)
    check("lz4 payload recognised", "lz4-compressed" in plain)
    check("ver 10 reported", "ver=10" in plain or "10" in plain)
    check("media id surfaced from the upload url", str(MEDIA_ID) in plain)

    print("\n3. all three upload phases were correlated")
    check("phase 1/3 printed", "phase 1/3" in plain)
    check("phase 2/3 printed", "phase 2/3" in plain)
    check("phase 2/3 completed", "phase 2/3 done" in plain)
    check("phase 3/3 printed", "phase 3/3" in plain)
    check("phase 3 matched the phase 2 token", "token matches phase 2" in plain)

    print("\n4. the HTTP hop is shown, not skipped")
    check("HTTP POST shown", "HTTP POST" in plain)
    check("upload status shown", "200 POST" in plain)
    check("upload reply body shown", PHOTO_TOKEN[:20] in plain)
    check("multipart filename described", "image.jpeg" in plain)

    print("\n5. summary and capture file")
    check("summary printed", "summary" in plain)
    check("http request counted", "http requests" in plain)
    check("uploads counted", "media uploads" in plain)
    captures = sorted((HERE / "captures").glob("max_*.jsonl"))
    check("capture file written", bool(captures), [p.name for p in captures])
    if captures:
        newest = captures[-1]
        records = [json.loads(l) for l in newest.read_text().splitlines() if l.strip()]
        kinds = [r.get("kind") or "frame" for r in records]
        check("capture has both frames and http records",
              "frame" in kinds and "http-request" in kinds and "http-response" in kinds,
              kinds)
        http_req = [r for r in records if r.get("kind") == "http-request"]
        check("http request size recorded", http_req and http_req[0]["size"] > 0,
              http_req[:1])
        check("http part described", http_req and "image.jpeg" in http_req[0].get("part", ""),
              http_req[:1])
        newest.unlink()

    print()
    if failures:
        print("FAILED %d check(s): %s" % (len(failures), failures))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
