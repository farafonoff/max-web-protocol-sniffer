# MAX Protocol — Findings from web.max.ru JS Bundles

Reverse-engineered purely from the static JS bundles in this directory (Vite build of **web.max.ru**, app version `26.10.1 (19297)`). No network traffic was used.

## 1. Bundle layout

| File | Size | Role |
|---|---|---|
| `web.max.ru__app_immutable_nodes_0.*.js` | 1.3 MB | App bootstrap + **OK/MAX Calls SDK** (signaling; `appName="ok.calls.sdk.js"`, sdk `2.8.13-beta.3`, apiClientVersion `1.1`) |
| `web.max.ru__app_immutable_chunks_CGK0xiLg.*.js` | 2.0 MB | **Core messaging protocol** (transport `lre`, app store `W`, sync) + i18n (RU/EN/UZ/PT/FR) |
| `web.max.ru__app_immutable_nodes_9.*.js` | 0.9 MB | UI screens |
| `web.max.ru__app_immutable_chunks_CIjzuX_N.*.js` | 0.3 MB | Protocol constants (WS URL, appToken, calls apiKey, version) |
| `web.max.ru__app_immutable_chunks_DHq1WUJS.*.js` | 66 KB | Reactive store lib; vendored BroadcastChannel + leader-elector |
| `web.max.ru__app_immutable_chunks_KJS7Jo4K.*.js` | 4 KB | Re-export shim of protocol types (`Api`, `Signaling`, `SignalingCommandType`, `TransportTopology`, `ConversationFeature`, `AuthData`, `ParticipantStatus`, …) |
| `…entry_app`, `…entry_start`, `nodes_1` | tiny | Vite entry points, status/error screen |
| `…workers_RenderWorkerEntrypoint`, `…browser-image-compression` | — | Web Workers (render, image compression) |

## 2. Constants (from `CIjzuX_N` chunk)

| Constant | Value | Meaning |
|---|---|---|
| WS endpoint | `wss://api.oneme.ru/websocket` | Main messaging WebSocket |
| appToken | `D9QQOhewNKDgudTuGUOjQpuapcJI6ZwXf8IavpN8uVM1` | Used as `tracerUploadConfig.appToken` (analytics), exposed as `window.APP_VERSION`-adjacent config |
| versionCode | `19297` | `versionName` `26.10.1 (19297)` |
| calls apiKey | `CNHIJPLGDIHBABABA` | Voice/calls SDK `apiKey` |
| device id key | `__oneme_device_id` | localStorage, persisted `crypto.randomUUID()` |
| auth key | `__oneme_auth` | localStorage, `{viewerId, token}` |
| calls auth key | `__oneme_calls_auth_token` | localStorage |

## 3. Transport (class `lre`)

- Binary WebSocket (`binaryType = "arraybuffer"`), single socket for the whole session.
- Incoming messages are exposed as an async iterable (`for await (msg of conn.messages())`).
- Reconnect: exponential backoff `min(2^t * 500ms, 10s)` with ±50 % jitter; 35 s connect timeout; on close resets `lastInSeq`/`nextOutSeq`/`loginSeq` and replays queued requests (`retryWhenReconnected` flag).
- Liveness:
  - server ping → pong (see opcode 1 below);
  - client sends `cmd(1, { interactive })` every 30 s; `interactive` = "app is idle or in active call" (idle detector based on visibility + input events).

## 4. Wire format

10-byte header + msgpack payload. All multi-byte fields little-endian unless noted.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | proto version | constant `10`; decoder warns on mismatch |
| 1 | 1 | `cmd` | `0`=request, `1`=response, `2`=request flushed after pending-login, `3`=error |
| 2 | 2 | `seq` | int16 LE; request/response correlation |
| 4 | 2 | `opcode` | int16 LE |
| 6 | 1 | compression ratio | `0` = raw; otherwise payload is **LZ4 block-compressed**; value = ⌈originalLength / compressedLength⌉ (max 255) |
| 7 | 3 | payload length | 24-bit big-endian |
| 10 | — | payload | msgpack, with int64/BigInt extension codec (ext type 1) |

- Compression engages only for payloads > 32 bytes. LZ4 is a custom in-chunk implementation (errors literally say `lz4: corrupt block`).
- Decoding a compressed payload: expected size = `payloadLen * ratio` (approximate upper bound).
- Errors surface as `msgpack.encode/decode` errors carrying `seq`, `opcode` and the raw header bytes.

## 5. Sequencing & request/response

- Client maintains `nextOutSeq` (starts at 0, wraps int16). `seq === 32767` forces the socket to close (seq-space rotation).
- `outQueue` (Map seq → {resolve, reject, opcode, payload, retryWhenReconnected}) correlates responses (`cmd:1`) and errors (`cmd:3`).
- **Pre-login gating**: requests issued via the high-level `cmd()` default to `waitForLogin: true` and are *not* put on the wire until the login roundtrip completes; on login success they are flushed with `cmd:2`. A small set of opcodes bypasses the gate and must be sent immediately when open: `[5, 6, 17, 18, 19, 23, 288, 289, 291, 294, 101, 109, 110, 115, 116, 224]`.
- Server errors (`cmd:3`) carry `{error, message, localizedMessage, title, description}`; error objects stringify as `[0xOPCODE error.code] message`.

## 6. Connection lifecycle

1. **Open** → client immediately sends **opcode 6 (init/session)**:
   ```jsonc
   { "userAgent": {
       "deviceType": "WEB", "pushDeviceType": "WEBPUSH",
       "locale": …, "deviceLocale": …, "osVersion": …, "deviceName": …,
       "headerUserAgent": navigator.userAgent, "isPwa": …,
       "appVersion": "26.10.1", "screen": "1080x1920 2.0x", "timezone": …
     },
     "deviceId": "<uuid>" }
   ```
2. Server responds to op 6 with session + config payload. If `__oneme_auth` exists locally, the client emits an auth event and issues **opcode 19 (login/resync)**:
   ```jsonc
   { "token": …, "chatsCount": 15, "lastLogin": …, "interactive": …,
     "chatsSync": …, "contactsSync": …, "presenceSync": -1,
     "draftsSync": …, "configHash": … }
   ```
3. Login response (op 19) returns `time` and (on first login) a fresh `token`; then the app runs a **full resync** (profile, config, contacts, presences, chats + first page of messages, drafts, folders, call history, …).
4. Auth errors `login.token | login.blocked | login.flood | user.not.found` → localStorage auth wiped, opcode **20 (forced logout)** event, socket disposed.
5. Opcodes **18 / 101 / 115 / 23 / 291** can carry new auth (`tokenAttrs.LOGIN` + `profile`) on any response; op **23** delivers an explicit token refresh.

## 7. Opcode map (observed in bundles)

### 7.1 Server → client pushes / system

| Opcode | Hex | Meaning | Payload (fields observed) |
|---:|---|---|---|
| 1 | 0x01 | ping (client answers with `cmd:1`, same seq) | — |
| 6 | 0x06 | session init response (config) | server config map |
| 19 | 0x13 | login/resync response | `{time, token?, profile, config, contacts, chats, messages, drafts, updates, chatMarker}` |
| 20 | 0x14 | forced logout / kick | — |
| 23 | 0x17 | auth/token event | `{token, profile}` |
| 128 | 0x80 | new message (server acks it client-side too: `{chatId, messageId}`) | `{chat, chatId, postId, message, unread, mark}` |
| 129 | 0x81 | typing indicator | `{chatId, userId, type}` |
| 130 | 0x82 | chat mark / unread update | `{chatId, userId, mark, setAsUnread, unread}` |
| 131 | 0x83 | contact upsert | `{contact}` |
| 132 | 0x84 | presence update | `{userId, presence}` |
| 134 | 0x86 | server config update | `{config}` |
| 135 | 0x87 | chat upsert (+ last reaction) | `{chat, lastReactedMessageId, lastReaction}` |
| 136 | 0x88 | media upload finished | `{audioId?, fileId?, videoId?, error?}` |
| 137 | 0x89 | incoming call | `{callerId, type, conversationId, conversationParams (vcp)}` |
| 142 | 0x8E | messages removed | `{chat, chatId, postId, messageIds[]}` |
| 150 | 0x96 | assets update | NOTIF_ASSETS_UPDATE |
| 152–153 | | ignored | — |
| 154 | 0x9A | delayed/scheduled message update | `{chatId, updateTypeId: 0 added / 1 fire-error / 2 removed / 3 fired, message?, messageIds?, lastDelayedUpdateTime}` |
| 155 | 0x9B | reactions (detailed invalidated, bulk upsert) | `{chatId, postId, messageId, yourReaction?}` |
| 156 | 0x9C | reaction update | `{chatId, postId, messageId, reactionInfo, yourReaction?}` |
| 159 | 0x9F | profile update | `{profile}` |
| 165 | 0xA5 | call history sync | `{action: ADD/REMOVE, callHistoryItems?, historyIds?, callHistorySync, prevCallHistorySync}` |
| 216 | 0xD8 | stories preview | `{storiesPreview}` |
| 243 | 0xF3 | pinned messages state | `{pinnedMessagesState}` |
| 277 | 0x115 | folders delta | folder upsert-delta |
| 293 | 0x125 | media transcription | `{chatId, messageId, mediaId, transcription, transcriptionStatus}` |

### 7.2 Client → server requests

| Opcode | Hex | Purpose | Payload (fields observed) |
|---:|---|---|---|
| 6 | 0x06 | init / device registration | `userAgent{…}, deviceId` (see §6) |
| 19 | 0x13 | login / resync | see §6 |
| 64 | 0x40 | **send chat message** | `{chatId, postId, type?, senderId?, message: {type?, text, cid, elements, link?, attaches?}, notify, delayedAttributes?}`; `link` = `{type: REPLY, messageId}` or `{type: FORWARD, messageId, chatId, postId}` |
| 67 | 0x43 | **edit message** | `{chatId, postId?, messageId, text, elements, attachments}` |
| 74 | 0x4A | fetch messages by id | `{chatId, messageIds[], readOnly?}` |
| 86 | 0x56 | show/hide chat | `{chatId, show}` |
| 89 | 0x59 | link preview / user-by-link | `{link}` |
| 34 | 0x22 | contact action | `{contactId, action: ADD/REMOVE/BLOCK/UNBLOCK}` |
| 36 | 0x24 | list blocked contacts | `{status: "BLOCKED", count, from}` |
| 41 | 0x29 | add contact by phone | `{phone, firstName?, lastName?}` |
| 46 | 0x2E | request phone auth code | `{phone}` |
| 50 | 0x32 | mark message read | `{type: "READ_MESSAGE", chatId, messageId, mark}` |
| 96 | 0x60 | list my sessions | `{}` |
| 97 | 0x61 | drop other sessions | `{}` |
| 22 | 0x16 | WebPush subscribe/unsubscribe | `{subscribe, pushToken, secretKey (VAPID auth), publicKey (p256dh)}` |
| 28 | 0x1C | resolve assets | `{type: STICKER|STICKER_SET|ANIMOJI|ANIMOJI_SET, ids[]}` |
| 32 | 0x20 | contacts by ids / group info | `{contactIds[]}` / members |
| 59 | 0x3B | group chat ops (members) | group member fields |
| 176 | 0xB0 | save draft (server-side) | `{chatId?, userId?, draft: {text?, elements?, replyTo?}}` |
| 177 | 0xB1 | discard draft | `{chatId?, userId?, time}` |
| 274 | 0x112 | save chat folder | `{id, title, include[], favorites[], filters[], options[]}` |
| 300 | 0x12C | assign chats to folder | `{folderId, userChatIds[]}` |
| 85 | 0x55 | call settings for conversation | `{conversationId}` → `{onlyAdminCanRecord, waitingHall, …}` |
| 199 | 0xC7 | auto-delete (self-destruct) profile | `{delete, type (twoFactor)}` |

> Opcodes 5, 17, 18, 101, 109, 110, 115, 116, 224, 288, 289, 291, 294 appear only in the pre-login allow-list / auth paths (login variants, device registration, auth exchange); their payloads were not all resolvable statically.

## 8. Sync & storage model

- **Full resync on (re)login** driven by cursors: `chatsSync`, `contactsSync`, `draftsSync`, `presenceSync`, `configHash`, plus `chatsCount` for the first messages page and `lastLogin`.
- **Push deltas** afterwards (opcodes §7.1); each collection keeps its own `syncTime` cursor that is reported at the next login.
- **Client storage**: IndexedDB persistent cache, enabled only when server config flag `web-persistent-cache` is true. On auth, `dbClient.open(viewerId)` + `restore()` (viewer, contacts, organization, botInfo).
- **Long messages** are chunked client-side using server config `max-msg-length`.
- **Server config** arrives in op 6/134 payloads; observed flags include `phone-auth-enabled`, `qr-auth-enabled`, `web-pwa-promo`, `web-persistent-cache`, `max-msg-length`, `calls-*` (calls SDK feature flags), `proxy`, `reg-country-code`, …
- IDs (`chatId`, `messageId`, `viewerId`, `userId`) are **BigInt** everywhere (msgpack int64 extension); chat ids may carry a `postId` part (forum topics).

## 9. Auth

- Token-based: `{viewerId, token}` kept in `localStorage.__oneme_auth`; refreshed in-place by ops 18/23/29/… ; phone-code (`op 46`) and QR-code flows available in UI (server flags above).
- Kick: op 20 or `login.*` errors → storage wiped, redirect to `/`.
- No client-side message encryption exists in the bundles — only `crypto.randomUUID`. Confidentiality is TLS + bearer token; tokens live in localStorage (XSS-exposed).

## 10. Media

- Uploads/downloads go over **separate HTTP endpoints** (URLs delivered server-side via the `downloadUpload` collection), with resumable ranges and per-type progress tracking; completion is signalled via op 136.
- Emojis served from `st.max.ru/emojis/`; images pre-compressed in a worker (`browser-image-compression`).

## 11. Multi-tab & app plumbing

- **Leader election across tabs** on `BroadcastChannel("max")` (vendored elector; `fallbackInterval: 2000`, `responseTime: 1000`). Only the leader tab performs certain duties; `isLeader` is exposed to the app.
- **Idle detector** (`ma`): visibility + focus + input events → drives `interactive` pings and background analytics.
- **Analytics**: tracer upload configured by `{versionName, versionCode, appToken}`; call telemetry spans (`msg_response`, `notif_received`, …) in the send flow.
- DevTools override storage for server config in dev builds.

## 12. Calls signaling (separate OK Calls SDK stack)

Voice/video is a distinct subsystem embedded in `nodes_0`:

- **Endpoints**: prod `https://api.mycdn.me`, `https://calls.okcdn.ru`; test variants on `calls-test.oneme.ru`, `apitest.ok.ru`, `videotestapi.ok.ru`, … selected by server config `calls-endpoint` + env.
- **Signaling transports**: WebSocket or **WebTransport** (`congestionControl: "low-latency"`, URL params add `compression=deflate-raw&ua=…`), chosen by `calls-sdk-wt-enabled` + browser support; falls back to WS on failure (`forceWebSocket`).
- **URL params**: `platform, appVersion, version` (protocolVersion **5 or 6** — 6 when `joinFromMultipleDevices`), `device, capabilities` (feature-flag string), `clientType`, and optionally `tgt` (connection type), `recoverTs` (last stamp for resumption), `peerId`, `partIdx/partCount` (participant-list chunking).
- **Reliability**: exponential reconnect with max delay/count from config; a "doctor" timer (`waitMessageDelay`) force-closes dead connections; close codes 4000-family for specific reasons (`conversation-ended`, `gen.obsoleteClient`, `invalid-token`, `participant-not-found`, `illegal-participant-state`, `service-unavailable`).
- **Media**: WebRTC datachannels carry control/animoji traffic (vmoji protocol versioned separately, default 1); VP8/VP9 encode/decode via WebCodecs with libvpx (WASM) fallback in workers.
- **Auth**: calls SDK has its own token flow (`accessToken/sessionKey/sessionSecretKey`, `onTokenExpired` → re-auth), plus `__oneme_calls_auth_token` in localStorage.
- Group-call concepts present: `waitForAdminInGroupCalls`, `addParticipant`, `hold`, `simulcast`, `maxParallelCalls: 2`, transparent audio, topology switch on reconnect.

## 13. Quick reference: minimal client handshake

```
CONNECT wss://api.oneme.ru/websocket  (binary)
→ frame: ver=10 cmd=0 seq=0 op=6  payload=msgpack({userAgent:{deviceType:"WEB",…}, deviceId:"<uuid>"})
← frame: ver=10 cmd=1 seq=0 op=6  payload={config, …} (+ saved session)
→ frame: ver=10 cmd=0 seq=1 op=19 payload={token, chatsCount:15, lastLogin, interactive, chatsSync, contactsSync, presenceSync, draftsSync, configHash}
← frame: ver=10 cmd=1 seq=1 op=19 payload={time, token?, profile, config, contacts, chats, messages, drafts, …}
← frames: cmd=1 op=128/129/130/… (pushes)
← frame: cmd=1 op=1 (ping)  →  reply cmd=1 op=1 (same seq)
← frame: cmd=3 op=<X> payload={error, message, …} (errors)
```

### Notes / confidence

- All findings are static; opcode payloads marked with "?" are partially inferred.
- Several request opcodes (5, 17, 288, 289, 294, 224, …) are only referenced in allow-lists; their semantics need dynamic capture.
- The `cmd:2` flush on login is an interpretation: held requests are re-emitted with cmd type 2 instead of 0.
