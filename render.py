"""Console rendering for decoded MAX frames.

Two jobs: redact credentials that show up in the auth handshake, and turn a
frame into something readable at a glance. Opcode-specific summarisers pull out
the fields that matter (who sent what, in which chat) so you rarely need to read
the raw payload.
"""

import json
import os
import re
import sys

from opcodes import Command, Opcode, command_name, opcode_name

# Credential-bearing payload keys, matched as whole lowercased key names.
# Substring matching is deliberately avoided: "authTokenType" contains "token"
# but is an enum, not a secret, and redacting it just hides useful information.
SECRET_KEYS = frozenset(
    {
        "token",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "logintoken",
        "verifycode",
        "password",
        "newpassword",
        "chatcachefingerprint",
        "secret",
        "credential",
        "otp",
    }
)

# Opcodes worth a human-readable summary line.
_INTERESTING = {
    Opcode.SESSION_INIT,
    Opcode.LOGIN,
    Opcode.LOGIN2,
    Opcode.AUTH_REQUEST,
    Opcode.AUTH,
    Opcode.AUTH_CONFIRM,
    Opcode.MSG_SEND,
    Opcode.MSG_EDIT,
    Opcode.MSG_DELETE,
    Opcode.NOTIF_MESSAGE,
    Opcode.NOTIF_CHAT,
    Opcode.NOTIF_TYPING,
    Opcode.NOTIF_PRESENCE,
    Opcode.NOTIF_ATTACH,
    Opcode.NOTIF_MSG_REACTIONS_CHANGED,
    Opcode.NOTIF_MSG_YOU_REACTED,
    Opcode.NOTIF_MARK,
    Opcode.NOTIF_MSG_DELETE,
    Opcode.PING,
    Opcode.CHATS_LIST,
    Opcode.CHAT_INFO,
    Opcode.PROFILE,
    Opcode.WEB_APP_INIT_DATA,
    Opcode.LOG,
    Opcode.DEBUG,
    # Media upload handshake: asks the server for a presigned URL. The bytes
    # then go over plain HTTP, not the socket, so pair this with http capture.
    Opcode.PHOTO_UPLOAD,
    Opcode.VIDEO_UPLOAD,
    Opcode.FILE_UPLOAD,
    Opcode.STICKER_UPLOAD,
}


def color_enabled():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("MAX_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


class Palette:
    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, text):
        if not self.enabled:
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def dim(self, t):
        return self._wrap("2", t)

    def bold(self, t):
        return self._wrap("1", t)

    def red(self, t):
        return self._wrap("31", t)

    def green(self, t):
        return self._wrap("32", t)

    def yellow(self, t):
        return self._wrap("33", t)

    def blue(self, t):
        return self._wrap("34", t)

    def magenta(self, t):
        return self._wrap("35", t)

    def cyan(self, t):
        return self._wrap("36", t)

    def grey(self, t):
        return self._wrap("90", t)

    def opcode(self, op):
        if op in (Opcode.PING, Opcode.LOG, Opcode.DEBUG):
            return self.grey(opcode_name(op))
        if op in (Opcode.MSG_SEND, Opcode.AUTH, Opcode.AUTH_REQUEST, Opcode.AUTH_CONFIRM):
            return self.magenta(opcode_name(op))
        if op in (Opcode.NOTIF_MESSAGE, Opcode.MSG_EDIT):
            return self.green(opcode_name(op))
        if op is not None and int(op) >= 128:
            return self.cyan(opcode_name(op))
        return self.yellow(opcode_name(op))


def redact(value, _depth=0):
    """Recursively replace credential values with a length-only marker."""
    if _depth > 24:
        return "<deep>"
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in SECRET_KEYS:
                if item is None or item == "":
                    out[key] = item
                else:
                    out[key] = "<redacted %s chars>" % _measure(item)
            else:
                out[key] = redact(item, _depth + 1)
        return out
    if isinstance(value, list):
        return [redact(item, _depth + 1) for item in value]
    return value


def _measure(value):
    if isinstance(value, (bytes, bytearray)):
        return len(value) * 2
    return len(str(value))


def human_size(n):
    if n < 1024:
        return "%dB" % n
    if n < 1024 * 1024:
        return "%.1fKB" % (n / 1024.0)
    return "%.1fMB" % (n / (1024.0 * 1024.0))


def preview(text, limit=110):
    if text is None:
        return ""
    flat = re.sub(r"\s+", " ", str(text)).strip()
    if len(flat) <= limit:
        return flat
    return flat[:limit] + "…"


def _dig(payload, *names):
    cur = payload
    for name in names:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(name)
        if cur is None:
            return None
    return cur


def _message_summary(payload):
    """NOTIF_MESSAGE / MSG_EDIT carry {"message": {...}}."""
    msg = _dig(payload, "message") or payload
    if not isinstance(msg, dict):
        return None
    parts = []
    chat = msg.get("chatId")
    mid = msg.get("id")
    sender = msg.get("sender")
    if chat is not None:
        parts.append("chat=%s" % chat)
    if mid is not None:
        parts.append("msg=%s" % mid)
    if sender is not None:
        parts.append("from=%s" % sender)
    text = msg.get("text")
    if text:
        parts.append('"%s"' % preview(text))
    attaches = msg.get("attaches")
    if attaches:
        parts.append(_attach_summary(attaches))
    reaction = msg.get("reactionInfo")
    if isinstance(reaction, dict) and reaction.get("totalCount"):
        parts.append("reactions=%s" % reaction.get("totalCount"))
    status = msg.get("status")
    if status:
        parts.append("status=%s" % status)
    return "  ".join(parts) or None


def _attach_summary(attaches):
    """One token per attachment: `PHOTO#46755532157 16KB` and friends.

    MAX serialises the attachment kind as `_type`, not `type` (pymax maps
    `AttachmentType.type` onto the `_type` wire alias), so check both.
    """
    if not isinstance(attaches, list):
        return "attach=%s" % preview(attaches, 60)

    parts = []
    for a in attaches[:6]:
        if not isinstance(a, dict):
            parts.append(preview(a, 24))
            continue
        kind = a.get("_type") or a.get("type") or "?"
        token = (
            a.get("photoId")
            or a.get("videoId")
            or a.get("fileId")
            or a.get("stickerId")
        )
        label = str(kind)
        if token is not None:
            label += "#%s" % token
        if a.get("width") and a.get("height"):
            label += " %sx%s" % (a["width"], a["height"])
        for size_key in ("size", "fileSize", "length"):
            if a.get(size_key):
                label += " " + human_size(
                    a[size_key] if isinstance(a[size_key], int) else 0
                )
                break
        parts.append(label)

    suffix = "" if len(attaches) <= 6 else ",+%d" % (len(attaches) - 6)
    return "attach=[%s%s]" % (",".join(parts), suffix)


def _upload_summary(payload):
    """PHOTO/VIDEO/FILE/STICKER_UPLOAD replies carry a presigned HTTP url.

    The media id lives in the url query, so pull it out for readability.
    """
    parts = []
    url = payload.get("url")
    if url:
        parts.append("url=%s" % preview(url, 110))
        ids = _query_ids(url)
        if ids:
            parts.append("ids=[%s]" % ",".join(ids[:8]))
    for key in ("photoId", "videoId", "fileId"):
        if payload.get(key) is not None:
            parts.append("%s=%s" % (key, payload[key]))
    if not parts and payload:
        parts.append("keys=[%s]" % ",".join(sorted(payload)[:8]))
    return "  ".join(parts) or None


def _query_ids(url):
    """Pull photoIds / videoIds / fileIds style params out of an upload url."""
    out = []
    try:
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(url).query)
    except Exception:
        return out
    for key, values in query.items():
        low = key.lower()
        if "id" in low and "track" not in low:
            out.extend(str(v) for v in values[:8])
    return out


def _chat_summary(payload):
    chat = _dig(payload, "chat") or payload
    if not isinstance(chat, dict):
        return None
    parts = []
    if chat.get("id") is not None:
        parts.append("chat=%s" % chat["id"])
    if chat.get("type"):
        parts.append("type=%s" % chat["type"])
    if chat.get("title"):
        parts.append('"%s"' % preview(chat["title"], 60))
    lm = chat.get("lastMessage")
    if isinstance(lm, dict):
        parts.append("last=msg%s" % lm.get("id"))
        if lm.get("text"):
            parts.append('"%s"' % preview(lm["text"], 50))
    if chat.get("newMessages"):
        parts.append("unread=%s" % chat["newMessages"])
    return "  ".join(parts) or None


def summarize(frame):
    """One-line human summary of a frame's payload, or None if nothing to add."""
    op = frame.opcode
    payload = frame.payload if isinstance(frame.payload, dict) else {}

    try:
        if op in (Opcode.NOTIF_MESSAGE, Opcode.MSG_EDIT, Opcode.MSG_DELETE):
            return _message_summary(payload)
        if op == Opcode.MSG_SEND:
            s = _message_summary(payload)
            return s or ("keys=%s" % ",".join(sorted(payload)[:8]))
        if op in (
            Opcode.PHOTO_UPLOAD,
            Opcode.VIDEO_UPLOAD,
            Opcode.FILE_UPLOAD,
            Opcode.STICKER_UPLOAD,
        ):
            return _upload_summary(payload)
        if op in (Opcode.NOTIF_CHAT, Opcode.CHAT_INFO, Opcode.CHATS_LIST):
            if op == Opcode.CHATS_LIST:
                chats = _dig(payload, "chats")
                if isinstance(chats, list):
                    return "%d chats" % len(chats)
                return None
            return _chat_summary(payload)
        if op in (Opcode.SESSION_INIT, Opcode.LOGIN, Opcode.LOGIN2):
            keys = ",".join(sorted(payload)[:10])
            return ("keys=[%s]" % keys) if keys else None
        if op == Opcode.PING:
            return "interactive=%s" % payload.get("interactive")
        if op == Opcode.NOTIF_TYPING:
            return "typing chat=%s from=%s" % (payload.get("chatId"), payload.get("sender"))
        if op in (Opcode.NOTIF_PRESENCE, Opcode.CONTACT_PRESENCE):
            return "user=%s presence=%s" % (
                payload.get("userId") or payload.get("id"),
                payload.get("presence") or payload.get("status"),
            )
        if op == Opcode.NOTIF_MSG_REACTIONS_CHANGED:
            return _message_summary(payload)
        if op == Opcode.PROFILE:
            return "profile id=%s" % payload.get("id")
        if op == Opcode.WEB_APP_INIT_DATA:
            return "web app init (%d keys)" % len(payload)
        if frame.error:
            return None
        if payload and not isinstance(payload, dict):
            return None
        if isinstance(payload, dict) and payload:
            return "keys=[%s]" % ",".join(sorted(payload)[:8])
    except Exception:
        return None
    return None


def format_frame(frame, palette, full=False, max_payload=1400):
    """Render one frame as a timestamped header plus indented detail lines."""
    ts = frame.ts or ""
    arrow = "→" if frame.direction == "send" else "←"
    cmd = frame.cmd
    try:
        cmd = Command(cmd)
    except ValueError:
        cmd = None
    cmd_label = command_name(frame.cmd)
    if cmd is Command.REQUEST:
        cmd_color = palette.magenta if frame.direction == "send" else palette.cyan
    elif cmd is Command.RESPONSE:
        cmd_color = palette.green
    elif cmd is Command.ERROR:
        cmd_color = palette.red
    else:
        cmd_color = palette.grey

    op_label = palette.opcode(frame.opcode)
    seq = frame.seq if frame.seq is not None else "-"

    header = "%s %s %s %s %s %s" % (
        palette.grey(ts),
        palette.bold(arrow),
        cmd_color("%-8s" % cmd_label),
        palette.grey("seq=%-5s" % seq),
        palette.bold("op=%-4s" % (frame.opcode if frame.opcode is not None else "-")),
        "%s %s" % (op_label, palette.grey(human_size(frame.size))),
    )

    lines = [header]

    if frame.note:
        lines.append("    %s" % palette.grey(frame.note))
    if frame.error:
        lines.append("    %s %s" % (palette.red("decode error:"), frame.error))

    summary = summarize(frame)
    if summary:
        lines.append("    %s" % summary)

    payload = redact(frame.payload) if isinstance(frame.payload, dict) else frame.payload
    if payload not in (None, {}, []):
        try:
            body = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            body = repr(payload)
        if not full and len(body) > max_payload:
            body = body[:max_payload] + "\n… %d more chars (use --full to see all)" % (len(body) - max_payload)
        for line in body.splitlines():
            lines.append("    %s" % palette.grey(line))

    return "\n".join(lines)


def format_http(method, url, palette, status=None, note=None, body=None,
                 req_size=None, max_body=1200, full=False):
    """Render an HTTP exchange (uploads bypass the socket framing entirely)."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = None

    if code is None:
        code_label = palette.bold("%-6s" % method.upper())
    elif 200 <= code < 300:
        code_label = palette.green("%d %s" % (code, method.upper()))
    elif 300 <= code < 400:
        code_label = palette.cyan("%d %s" % (code, method.upper()))
    elif code >= 400:
        code_label = palette.red("%d %s" % (code, method.upper()))
    else:
        code_label = palette.yellow("%s %s" % (code, method.upper()))

    lines = [code_label + " " + palette.bold(url)]
    bits = []
    if req_size is not None:
        bits.append("sent %s" % human_size(req_size))
    if note:
        bits.append(note)
    if bits:
        lines.append("    " + palette.grey("  ".join(bits)))

    if body not in (None, b"", ""):
        if isinstance(body, (bytes, bytearray)):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                lines.append("    " + palette.grey(
                    "<%d bytes of binary, not shown>" % len(body)
                ))
                return "\n".join(lines)
        text = body if isinstance(body, str) else str(body)
        if not full and len(text) > max_body:
            text = text[:max_body] + "\n… %d more chars (use --full)" % (len(text) - max_body)
        for line in text.splitlines():
            lines.append("    " + palette.grey(line))
    return "\n".join(lines)


def format_banner(text, palette):
    return "%s %s %s" % (palette.grey("───"), palette.bold(text), palette.grey("───"))


def should_show(frame, palette, verbose):
    """Filter out the boring frames unless --verbose."""
    if verbose:
        return True
    if frame.error:
        return True
    if frame.opcode in _INTERESTING:
        return True
    if frame.opcode is None:
        return True
    return False
