# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Multi-module layout

This repo contains **four Go modules**, intentionally split so the core
library never pulls heavy dependencies (gVisor) into its graph:

| Path | Module path | Purpose | Heavy deps |
|---|---|---|---|
| `/` | `github.com/n0madic/go-openvpn` | Core OpenVPN 2.6+ client library + `pkg/ovpn` (.ovpn parser). Pure stdlib + `golang.org/x/crypto`. | none |
| `pkg/netstack/` | `github.com/n0madic/go-openvpn/pkg/netstack` | gVisor userspace TCP/IP stack on top of the tunnel `net.Conn`. | `gvisor.dev/gvisor` |
| `examples/netstack-http/` | `github.com/n0madic/go-openvpn/examples/netstack-http` | Standalone HTTP-over-netstack demo. | (transitively gVisor) |
| `cmd/openvpn2socks/` | `github.com/n0madic/go-openvpn/cmd/openvpn2socks` | SOCKS5 proxy CLI. | (transitively gVisor) |

Each non-root module has its own `go.mod` with `replace` directives pointing
at sibling dirs. **Run `go build`/`go test` from inside each module's
directory** — the root `go.mod` is not a workspace; there is no top-level
`go test ./...` that covers everything.

## Common commands

### Per-module unit tests

```bash
go test -race -count=1 ./...                        # from repo root: core lib + pkg/ovpn + 7 internal/ pkgs
cd pkg/netstack && go test -race -count=1 ./...
cd cmd/openvpn2socks && go test -race -count=1 ./...
```

### Real-server integration suite (Docker, OpenVPN 2.6.x via `alpine:latest`)

```bash
cd test/integration
make all          # pki + up + wait + (3-module test run) + down
make up && make wait      # just bring the server up
make test                  # run all 3 modules' integration tests (-tags=integration)
make logs                  # tail server logs
make down                  # stop and remove the container
make clean                 # also wipe ./pki
```

`make test` runs three invocations sequentially:
1. `test/integration/` (core library, 5 tests)
2. `pkg/netstack/` (userspace TCP/IP, 2 integration tests)
3. `cmd/openvpn2socks/` (SOCKS5 daemon, 5 e2e tests)

To switch back to OpenVPN 2.7.x: change `FROM alpine:latest` →
`FROM alpine:edge` in `test/integration/Dockerfile`.

### Running individual tests

```bash
go test -race -run TestRealRekey -v ./test/integration/...
go test -tags=integration -run TestRealSOCKS5UDPAssociate -v ./...
```

### Verification end-to-end (manual)

```bash
# From repo root, with valid OpenVPN credentials:
export OVPN_USER='...'; export OVPN_PASS='...'
go run ./examples/ovpn-ping/ -config ~/profile.ovpn
go run ./cmd/openvpn2socks/ -config ~/profile.ovpn
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me  # different terminal
```

## Architecture (big picture)

### Wire layer stack (`internal/`)

The OpenVPN client is built bottom-up as separately testable layers:

```
internal/transport       UDP raw / TCP-with-16BE-length-prefix (PacketConn)
internal/tlscrypt        AES-256-CTR + HMAC-SHA256 wrapper (v1) +
                         tls-crypt-v2 client bundle (Kc + WKc)
internal/tlsauth         tls-auth control-channel HMAC (SHA1/256/512,
                         digest-size keys, swap_hmac byte order). Reuses
                         tlscrypt's key parsing + KEY_DIRECTION mapping.
                         HMAC-only (no encryption); satisfies the same
                         controlWrapper interface as tlscrypt.
internal/reliable        Per-key-id reliability shim: msg_pid, retransmit
                         (1s→16s exp backoff, 8 retries), TCP-style fast
                         retransmit (3 higher-msgPID ACKs short-circuit
                         the backoff timer), ACK piggyback/standalone,
                         in-order delivery to crypto/tls via reliable.Adapter
internal/control         Handshake state machine: HARD_RESET → TLS over
                         reliable.Adapter → KEY_METHOD 2 → PUSH_REQUEST →
                         TLS-EKM key derivation
internal/data            AEAD seal/open, KeySlot (kid+peerID+ciphers+sendPID+replay),
                         sliding-bitmap replay protection
internal/proto           Opcode encoding, packet headers, KEY_METHOD 2 codec,
                         PUSH_REPLY parser, peer-info builder
internal/workers         Tiny lifecycle manager for the session's
                         long-running goroutines: named workers, panic
                         recovery (logged, triggers Shutdown — process
                         doesn't crash), sync.Once-guarded shutdown,
                         shared cancellation context. Used by
                         internal/session so all of its goroutines share
                         one ctx + WaitGroup with uniform observability.
internal/session         Orchestrator. Goroutines per active session
                         (all via workers.Manager — named, panic-
                         recovered, cancelled together):
                         readLoop (demuxes by opcode+key-id; on a
                         transport read error before s.ctx is cancelled
                         it setCloseErr's a *RestartError + spawns
                         closeAsync so AutoReconnect catches the socket-
                         died-but-no-watch-fired post-suspend path, else
                         closeErr=nil freezes the tunnel),
                         writeLoop + tickLoop (per reliable.Layer, 2 per
                         key-id), rekeyWatch, controlChannelReader
                         (post-handshake RESTART/EXIT/INFO dispatcher),
                         keepaliveLoop, pingRestartWatch, dataActivityWatch,
                         hardResetWatch, wakeDetectorWatch, statsLogger
                         (each watchdog's contract is in points 7-11).
                         Holds per-key-id slot + layer tables for rekey
                         transition windows.
```

### Public API (`openvpn.go`, `conn.go`)

- `Dial(ctx, *Config) (*Client, error)` — produces a fully-up tunnel.
  `ctx` scopes the handshake only; after Dial returns, the Client is
  rooted at its own Background-derived lifetime context, so a caller's
  `defer cancel()` doesn't tear down the session. Callers who want
  SIGINT to also break blocked Tunnel I/O run their own
  `go func() { <-ctx.Done(); cli.Close() }()`.
- `Client.Tunnel() net.Conn` — datagram-oriented: 1 `Read` = 1 IP packet,
  1 `Write` = 1 IP packet. The handle is **stable across `AutoReconnect`-
  driven session replacements** — blocked Reads transparently resume on
  the new session. `Tunnel.Close()` is documented no-op (use `Client.Close()`);
  consumers like `pkg/netstack` poke `SetReadDeadline` to unblock a pending
  Read because Close alone won't.
- `Tunnel.Read`/`Write` honour `SetReadDeadline`/`SetWriteDeadline` and
  surface `os.ErrDeadlineExceeded`. When `AutoReconnect` is on, reconnect
  itself is bounded by the per-call deadline: a slow `RESTART,60` won't
  pin a `Read` past its deadline — the call returns `ErrDeadlineExceeded`
  and the next call resumes reconnect.
- `Client.PushedOptions() PushReply` — re-queried lazily, so post-reconnect
  values are reflected.
- `Client.Close()` — sends `EXIT\0` over the control channel
  (explicit-exit-notify) and waits for the reliable layer to drain it.
- `Config.DialTransport TransportDialer` — optional injectable transport.
  When non-nil the library calls it instead of dialing a UDP/TCP socket, so
  OpenVPN runs over a proxy / obfuscation layer / any caller-controlled
  `net.Conn`. `openvpn.Transport` aliases the internal `transport.PacketConn`;
  build one from a `net.Conn` with `NewStreamTransport` (16-bit BE length-
  prefix framing, `proto tcp`) or `NewDatagramTransport` (one read = one
  packet). The factory is invoked by the internal helper `dialSession`
  (shared by `Dial` + `reconnect`), so it runs once per (re)connect and
  **must return a fresh connection each call** — `AutoReconnect` closes the
  previous transport and expects a brand-new one. `Network`/`RemoteAddr`
  become optional hints (validation moved from `session.validateConfig` to
  `session.Dial`, so `DialWithTransport` accepts them empty). On factory
  error or nil return `dialSession` wraps/reports it; on handshake failure
  it closes the transport (DialWithTransport contract).
- `Config.AutoReconnect` + `ReconnectMaxAttempts` + `ReconnectMaxInterval`
  — when set, server `RESTART` is absorbed without surfacing to the user.
  `Dial` also spawns a background `sessionWatcher` that polls `s.CloseErr()`
  every `sessionWatchPeriod=500ms` and reconnects on a `*RestartError`
  WITHOUT needing `Tunnel.Read`/`Write` to observe it. This matters in
  netstack mode: the data path runs through `SetIngressHandler`, nobody
  sits in `Tunnel.Read`, so a `wakeDetectorWatch` RestartError after suspend
  would otherwise sit unconsumed (gVisor TCP timed out, apps not yet
  retrying) and zombie until manual intervention. The watcher exits on
  terminal errors (`ErrAuthFailed`, `ErrReconnectGaveUp`, `ErrClosed`,
  `ctx.Canceled`) or a non-restart close. `reconnectMu` serialises it with
  the `Tunnel.Read/Write` reconnect path; whichever wins, the other sees
  `c.session() != failed` and returns nil.
- `Client.RequestRestart(reason string)` — application-level escape hatch
  that forces the current session to close with a `*RestartError` so
  `AutoReconnect` re-dials. Useful for external monitoring / manual
  session refresh / tests. The Tunnel handle survives — blocked Reads
  resume on the new session.
- `Client.OnReconnect(fn func(PushReply)) (detach func())` — callback fired
  every time AutoReconnect installs a fresh session. **Critical** for
  anything caching a tunnel-IP-dependent value (gVisor NIC address, bound
  sockets, host routes): the server assigns a *new* `LocalIP` per session
  (and may change Gateway/Routes/MTU), so not refreshing means post-reconnect
  packets carry the OLD source IP and the server silently drops them — the
  "works for a bit, reconnects, then nothing works forever" zombie-loop bug.
  **Always call the returned detach from your Close path** if the hook's
  target outlives shorter than the Client, else the closure keeps a torn-down
  target alive and may deref dead fields. `pkg/netstack/netstack.go::Net.New`
  registers via this hook so the gVisor NIC stays in sync; `Net.Close`
  invokes the detach.

### Key protocol nuances (caught against real OpenVPN — preserve when editing)

1. **tls-crypt v1 is HMAC-SIV**: the HMAC-SHA256 tag is BOTH the authenticator
   AND the AES-256-CTR IV (16-byte IV = 16-byte HMAC truncation).
2. **tls-crypt packet-id is 8 bytes** (uint32 counter + uint32 net_time),
   not 4. Mixing this up silently breaks against real servers.
3. **KEY_METHOD 2 always includes username/password fields** (empty when
   not using `auth-user-pass`). The fields are on the wire either way.
4. **AEAD data packets place the tag BEFORE the ciphertext** (tag-prefix
   layout, matching `crypto.c::openvpn_encrypt_aead`). On-wire frame:
   `opcode_kid (1) || peer_id (3) || packet_id (4) || tag (16) || ciphertext`.
   The `IV_PROTO_AEAD_TAG_END` bit is NOT advertised — Go's `cipher.AEAD.Seal`
   emits `ct||tag`, so `Slot.Seal` moves the tag into its prefix slot
   in-place. Don't "fix" this to tag-at-end without also flipping the
   IV_PROTO bit and the layout in `slot.go`.
5. **Client must wait for `HARD_RESET_SERVER` before sending `P_CONTROL_V1`**
   (the TLS Hello). `reliable.Layer.Write` blocks on `remoteCond` until
   the peer's hard-reset arrives — strict servers (ProtonVPN) drop the
   TLS Hello otherwise. **Do not** remove this gating.
6. **OpenVPN PEM header for tls-crypt static key uses lowercase `key`**:
   `-----BEGIN OpenVPN Static key V1-----`. Both cases are accepted on
   read but emit with lowercase.
7. **Keepalive is mandatory; `applyKeepaliveDefaults` fills it when the
   server is silent.** Real servers push `ping N, ping-restart M` and expect
   a PING every N seconds; if M seconds pass without inbound data they drop
   us. Some providers (ProtonVPN) don't push these, so we apply defaults
   (`defaultPingInterval=15s` / `defaultPingRestart=60s`); pushed values win
   when present. `session.keepaliveLoop` emits the 16-byte `proto.PingMagic`
   (`2a 18 7b f3 64 1e b4 cb 07 ed 2d 0a 98 1f c7 48`, per
   `ping.c::ping_string`) as a regular P_DATA_V2 via the active slot. **PING
   is suppressed while any outbound went out in the last `PingInterval`** —
   matches upstream `forward.c::process_outgoing_link` resetting
   `ping_send_interval` on every outbound. Loop samples at `interval/4`
   (≥250ms) so a PING fires promptly once silence is crossed. PINGs count as
   outbound (loop-local `lastPingSent`); user data resets `s.lastUserOutbound`.
   **`lastUserOutbound` is set ONLY by `Session.WriteCtx`, NOT
   `keepaliveLoop`** — so `dataActivityWatch` (point 9) treats PINGs as
   overhead, not user activity. PingMagic's first nibble (`2`) is not a valid
   IP version, so `pkg/netstack`'s IPv4/IPv6 demux drops them naturally;
   `handleDataIn` also filters them from direct `Tunnel.Read`.
   `session.pingRestartWatch` is the standard watchdog: `now - lastInbound
   >= ping-restart` ⇒ `setCloseErr(&RestartError{...})` ⇒ `Close()` ⇒
   AutoReconnect. Don't gate the loops on push-reply being non-zero — that
   breaks providers that don't push. Keepalive `WritePacket` errors are
   non-fatal: log Debug and `continue`; bailing on the first ENOBUFS would
   mute keepalives for the session (the second half of the point-8
   production failure). **`ping_in_total=0` is normal**: a server's
   `ping_send_timeout` fires only when it has no outbound, so during active
   traffic it never PINGs us — `pingRestartWatch` survives because user data
   updates `lastInbound` (link-options.rst: "ping ... or other packet").

7b. **`ENOBUFS` on kernel UDP send must apply backpressure, not just
   error.** Even with `SO_SNDBUF` bumped to 4 MiB, a sustained burst
   (speedtest, bulk upload) will fill it faster than the kernel can
   drain to the wire. Returning the error straight to the caller —
   especially gVisor TCP — lets it queue the packet for retransmit
   instead of slowing its send rate; the retransmit also hits a full
   buffer and the cycle amplifies into a retransmit storm that we
   watched cause 10,000+ ENOBUFS errors in 4 minutes, after which the
   tunnel was effectively dead because the server gave up on us. The
   correct behaviour is to **block the writer goroutine** for a brief
   backoff (`enobufInitialBackoff=500µs`, exponential up to
   `enobufMaxBackoff=16ms`, capped at `enobufMaxTotalSleep=1500ms` per
   call) — same mechanism kernel TCP/IP stacks use to propagate
   backpressure to user-space via EAGAIN. gVisor's TCP send rate then
   naturally throttles to match the wire drain rate without
   amplification. After 1500ms total backoff, we DO return the error
   (gVisor TCP will retransmit on its own schedule, lossless; UDP/
   keepalive callers either retry at the next interval or are
   transient enough to lose). Successful retries are counted in
   `statsENOBUFSRetries` and surfaced as `enobufs_retries_total` /
   `delta_enobufs_retries` in `statsLogger` (delta > 10 escalates to
   WARN level so operators see sustained pressure without `-v`).
   Don't remove this — without it, speedtest poisons the tunnel
   permanently.

8. **macOS default `SO_SNDBUF` (~9 KiB) is too small for burst load.**
   gVisor TCP/UDP under heavy concurrent traffic (speedtest, parallel
   HTTP/2 fan-out) easily generates a burst that exceeds the OS UDP
   send buffer. The kernel rejects writes with `ENOBUFS` and packets
   are silently dropped; keepalives stop reaching the wire, the server
   eventually times us out, and the tunnel "freezes" while still looking
   alive at the protocol level. `internal/transport/udp.go::tuneSockBufs`
   raises `SO_SNDBUF` and `SO_RCVBUF` to `kernelSockBufBytes = 4 MiB`
   (kernel silently clamps to `kern.ipc.maxsockbuf` on macOS /
   `net.core.wmem_max` on Linux). Don't remove this without measuring
   loss under burst load.

9. **`pingRestartWatch` alone is not enough — server PINGs can fake
   liveness.** Servers with `keepalive N M` PING us every N seconds, and
   `handleDataIn` bumps `lastInbound` on **any** decrypted inbound,
   *including* the PINGs it then filters out. Several failure modes (gVisor
   link stall, server data-path glitch, an intermediate device dropping user
   traffic) leave PINGs flowing while real bytes are dropped —
   `pingRestartWatch` never fires and the user must restart manually.
   `session.dataActivityWatch` is the second-tier watchdog: it tracks
   `lastDataInbound` (non-PING, set in `handleDataIn`) and `lastUserOutbound`
   (set in `Session.WriteCtx`, NOT `keepaliveLoop` which goes direct to
   `transport.WritePacket`). When the user is sending (`sinceOut <
   threshold`) but no real data arrived in `DataActivityStuckThreshold`
   (steady 60s), it fires `RestartError` like pingRestartWatch, surfacing
   through `Read`/`Write` for AutoReconnect.
   **Adaptive two-phase threshold:** for the first `DataActivityFastWindow`
   (2min) after session-up it uses the tighter `DataActivityWarmupFast`
   (10s) / `DataActivityStuckThresholdFast` (20s) pair, then relaxes to
   steady. Rationale: a freshly-handshaken session is empirically far more
   likely to be wedged (server state loss for the prior peer-id, upstream
   rate-limit/blackhole keyed on something stable across reconnect — public
   IP, peer-info fingerprint — that the new handshake doesn't clear, NAT
   drift, gVisor TCP zombies on the old tunnel IP). Spending the full 60s
   confirming each is the difference between a few-second jitter and a
   minute-long freeze (2026-05-15 prod log: wedged ~32s before the user
   SIGKILL'd). Fast values are clamped at runtime to <= steady so tests with
   short explicit steady values (e.g. 200ms/500ms) aren't slowed by defaults.
   Trigger log records `phase=fast/steady` + elapsed `age`.
   **L4-aware — `aggregate` alone is not enough.** Aggregate `lastDataInbound`
   is fed by ANY non-PING inbound regardless of L4 family. 2026-05-15
   19:51-19:55: ~4s post-reconnect the server selectively dropped all TCP
   responses while UDP DNS replies dribbled in ~once a minute, so `sinceIn`
   reset on every DNS reply, the watchdog never tripped, and the tunnel sat
   wedged ~4min. So `Session` also tracks `lastDataInbound{TCP,UDP}` /
   `lastUserOutbound{TCP,UDP}`, populated from `sniffL4` in `handleDataIn`
   and `Session.WriteCtx`. The pure `decideActivityStall` checks all three
   pairs and fires on first match — per-L4 wins over aggregate so the log
   records the most specific cause (`signal=tcp/udp/aggregate`). When an L4
   inbound was never observed (fresh session that only sent TCP) it uses
   session `age` as the inbound floor, so a never-replied TCP flow trips the
   watchdog instead of hiding behind a zero timestamp; the aggregate channel
   deliberately does NOT use that floor (it required both sides observed
   once, kept for test stability). `sniffL4` mirrors
   `pkg/netstack/endpoint.dispatchInbound`, kept private to session so the
   watchdog doesn't drag a netstack dep into the core library. Thresholds
   are Config-tunable (sub-second in tests). Don't unify with
   pingRestartWatch — independent by design so one fires no matter which
   signal is fake.

10. **`handleDataIn` must NOT block on `ingressCh`.** The
    decrypt-and-forward path runs inside `session.readLoop`'s single
    goroutine. If the consumer (gVisor link endpoint reader) stalls,
    `ingressCh` fills (default capacity 256), and a blocking
    `s.ingressCh <- ip` would freeze `readLoop` — which would then
    stop pulling encrypted packets off the OS UDP socket, back-press
    until the OS buffer overflowed, and silently drop everything
    including future PINGs (round-trip: tunnel goes from "looks alive"
    to "actually dead" with no recovery signal). The `select` has a
    `default` branch that increments `statsDroppedFull` and discards
    the IP packet; standard network behaviour, gVisor TCP fills any
    gaps via retransmits. `statsLogger` logs at WARN when drops appear
    so the operator sees it. PINGs `return` before the select so they
    never participate in the back-pressure.

11. **Laptop sleep/resume needs explicit reconnect — `pingRestart`
    doesn't catch it.** A suspended laptop freezes the OpenVPN UDP
    socket. The server, meanwhile, sees us stop talking and after its
    own ping-restart (typically 60s) drops session state. On wake, the
    client resumes sending `P_DATA_V2` packets on the old key but the
    server no longer has matching state — it replies with
    `P_CONTROL_HARD_RESET_SERVER_V2` ("re-handshake, please"). Our
    `handleControlIn` recognises these via `isStrayUnwrap` and bumps
    `statsHardResetIn` (a strict subset of `statsStrayHandshake`).
    `session.hardResetWatch` polls that counter every 5s and fires
    `RestartError{Reason:"server hard-reset"}` once the count crosses
    `hardResetThreshold=3`. Belt-and-braces, `session.wakeDetectorWatch`
    ticks once per second and notices any wall-clock jump greater than
    10s — a normal scheduler delay is well under one tick, so anything
    larger is almost certainly suspend; fires
    `RestartError{Reason:"wake from sleep"}` so AutoReconnect kicks in
    immediately rather than waiting on ping-restart with stale keys.
    **Both timestamps used by `wakeDetectorWatch` are
    `time.Now().Round(0)` — stripping the monotonic component is
    MANDATORY on macOS.** Go's monotonic clock is backed by
    `mach_absolute_time`, which does NOT advance during suspend, so a
    monotonic-only diff across a suspend boundary returns ~0 and the
    watch never fires. Wall-clock comparison (forced by `.Round(0)`)
    survives. `openvpn.Client.sessionWatcher` performs the same
    wall-clock gap check at 500ms cadence as a second layer — if the
    session-level watch's ticker glitches across suspend, the
    Client-level one observes the same gap and calls `RequestRestart`.
    `pingRestartWatch` alone misses this scenario because inbound
    HARD_RESET packets bump `lastInbound` (handleControlIn updates it
    before discarding strays) — so without these two extra watchdogs
    the client sat in a useless zombie state. Don't merge wakeDetector
    into hardResetWatch: the two fire on independent evidence.
    `statsLogger` surfaces both `delta_stray_handshake` and the new
    `delta_hard_reset_in` so an operator sees the server-side give-up
    long before either watch crosses its threshold.

### gVisor netstack adapter (`pkg/netstack/`)

`Net.DialContext` supports both `tcp[/4/6]` and `udp[/4/6]`. Hosts must be
literal IPs — DNS resolution is the caller's responsibility (see
`cmd/openvpn2socks/resolver.go` for tunneled-UDP DNS). The `endpoint`
inside is a `stack.LinkEndpoint` that pumps IP packets between the gVisor
stack and the tunnel `net.Conn` without any link-layer header
(ARPHardwareNone, MaxHeaderLength=0).

**Conservative NIC MTU (`safeInnerMTU=1400`):** the gVisor NIC's
MTU is always clamped to 1400, regardless of what the server's
PUSH_REPLY says. With OpenVPN encap (24 B) + outer UDP (8 B) +
outer IPv4 (20 B) = 52 B of overhead, an inner IP packet of 1400
becomes a 1452-byte wire datagram — well under 1500 (ethernet),
1492 (PPPoE), 1480 (VPN-in-VPN). This is the architectural
equivalent of the official OpenVPN client's runtime MSS clamping
(`mssfix=1492` rewriting TCP MSS option on every TCP SYN, see
`src/openvpn/mss.c::mss_fixup_dowork`) — but **simpler in our
architecture**: gVisor *is* the OS stack for apps inside the
tunnel, so configuring its NIC MTU directly causes gVisor TCP to
auto-negotiate the right MSS (NIC_MTU - 40 = 1360) on every SYN
it emits; apps respect it, no runtime packet rewriting needed.
Without this, a naive 1500-byte inner MTU produces ~1552-byte
outer datagrams that fragment or silently drop on any path with
a strict 1500-byte MTU — which manifests as "tunnel works for a
while then degrades under sustained TCP load", a pattern we hit
in early testing. Applied at both `New` time and on every
reconnect via `clampInnerMTU` so a server pushing a different MTU
after AutoReconnect still gets clamped.

**Reconnect synchronisation:** the NIC address / routes / MTU are NOT
fixed at construction. `Net.New` registers an `openvpn.Client.OnReconnect`
hook that re-runs `Net.applyPushReply` against every freshly-installed
session's PUSH_REPLY. Without this, the NIC keeps the *first* session's
tunnel IP even after reconnect, so post-reconnect packets carry the old
source IP and the server drops them — there's no protocol-level error
back, just silent black-hole. The hook updates IPv4 + IPv6 addresses
(new before old, no transient unconfigured-NIC window), reinstalls the
route table (`SetRouteTable` replaces, not merges), and refreshes the
endpoint MTU.

**Zombie-endpoint cleanup on reconnect (unconditional):** existing TCP/UDP
gVisor conns bound to the OLD local IP become zombies when the tunnel IP
changes — they retransmit with a now-invalid src IP, the server drops them,
and gVisor TCP takes 60-120s to give up, so apps stall. To match the OS
kernel's `RTM_CHANGE` on utun (which `ECONNRESET`s existing sockets the
moment the interface address changes), `Net` tracks every `net.Conn` from
`DialContext` in an `activeConns sync.Map` (via a `trackedConn` that
deregisters on `Close`). The OnReconnect hook runs `applyPushReply` to
install the new addresses, then **unconditionally** force-closes every
tracked conn via `closeActiveOnReconnect` — apps see an immediate error,
retry, and the new gVisor endpoint binds to the current local IP and
registers with the new server session. Pre-/post-reconnect IPs are logged
but no longer drive policy.

**Why unconditional, not just "IP changed":** an earlier version preserved
conns when the tunnel IP stayed the same, assuming existing 4-tuples
remained valid (server NAT routes by IP, not peer-id). Field evidence killed
that: ProtonVPN routinely hands back the same local IP across reconnects
while the server-side session is brand new (different peer_id) with the old
connection state gone — so even with the same 4-tuple the server doesn't
route our old conns, gVisor TCP retransmits 60-120s, apps stall, and
`dataActivityWatch` fires a *second* reconnect seconds later. Log symptom: a
healthy "reconnect successful" then `tcp_current_established>0` with zero TCP
delta_in for a minute, then another reconnect. Force-closing everything
restores liveness in under a second. The `trackedConn` wrapper forwards
`CloseWrite()`/`CloseRead()` so the `socks5_tcp.go::proxy` type assertion
(`interface{ CloseWrite() error }`) still matches TCP-backed conns; for UDP
they're no-op safe.

**openvpn2socks-level companion fix:** `connRateLimiter.Reset()` is
invoked from a second `cli.OnReconnect` hook installed in `main.go`.
Without it, the per-host CONNECT burst limiter would refuse the
flood of legitimate retries that follow the netstack-level
force-close (browser tab fan-out reopening dozens of conns to the
same target IP in <1s) with `repConnRefused` for the first window,
even though the new tunnel is otherwise healthy.

**Data-path observability:** the LinkEndpoint exposes atomic
counters for every IP packet it sees in each direction, bucketed
by L4 protocol via a 1-byte sniff of the IP header
(`statsOutPackets`, `statsInPackets`, `statsInTCP`, `statsInUDP`,
`statsInICMP`). These are independent from the session-level
`statsOutboundOK` counter (which counts ALL transport writes
including PINGs and other non-gVisor traffic) — divergence
between the two localises whether a stuck data path is inside or
outside the netstack. `statsLoggerLoop` dumps the counters plus
key fields from `stack.Stats()` (TCP retransmits/resets/send-
errors, UDP packets-sent/received/unknown-port, IP packets/
malformed, DroppedPackets) every `statsLogPeriod=30s` at Debug
level — anything unusual auto-escalates to Warn so `-v` is not
required to see real problems.

**Pure observability — no actions.** An earlier "data-path health watchdog"
goroutine called `cli.RequestRestart` on app-level "TCP-deaf"/"UDP-deaf"/
"TCP-RST-storm" signatures, escalating to `os.Exit(99)` after two triggers.
**It was removed** — every failure case on a real ProtonVPN tunnel was the
watchdog creating the problem: the triggering metric (DNS UDP timeout,
transient RST burst from busy browsing) was an app-level hiccup, not a dead
tunnel — the protocol layer flowed, `dataActivityWatch`/`pingRestartWatch`
weren't firing. Its AutoReconnect changed the tunnel IP; gVisor TCP
endpoints on the OLD IP became zombies retransmitting an invalid src IP, the
server dropped them, `ep_in_tcp` read zero, the watchdog called that
"tcp-deaf" and hit `os.Exit(99)`. The official OpenVPN CLI runs stably for
hours against the same endpoint with no such gymnastics. The counters and
`statsLoggerLoop` stayed (useful for diagnosis). **Lesson: don't act on
app-level metrics when a protocol-level self-healing layer
(`pingRestartWatch`, `dataActivityWatch`, `hardResetWatch`, server RESTART)
already exists** — they're noisier than the protocol's own keepalive/restart
signals, and acting on them turns false signals into real outages.

**Consecutive-stall surrender (protocol-level, NOT app-level).** A different
failure mode — an upstream rate-limit/blackhole keyed on something stable
across reconnects (most plausibly our public IP or peer-info fingerprint,
NOT the UDP source port: `transport.Dial` re-`connect(2)`s each cycle, so
the kernel already hands us a fresh ephemeral port) — where every
AutoReconnect lands a fresh handshake but the session is born broken: TCP
outbound flows, PINGs arrive, but no real inbound ever does, so
`dataActivityWatch` fast-phase trips at age ~20s, we reconnect, trip again,
and spin forever, the tight loop continuously refreshing the upstream
cooldown timer. The fix is in `openvpn.Client.reconnect` (NOT netstack — see
above). Pure `decideStallSurrender(lifetime, closeErr, counter, max,
threshold)` returns the updated counter + a surrender flag: a stall close
shorter than `Config.StableSessionThreshold` (60s) increments the counter;
any other reason or any long-lived session resets it to 0; reaching
`Config.MaxConsecutiveStalls` latches `c.gaveUp` and closes
`Client.Unrecoverable()`. `cmd/openvpn2socks/main.go` defaults
`MaxConsecutiveStalls=3` and cancels `rootCtx` on that close, exiting code 1
so a supervisor (launchd/systemd/`until openvpn2socks; do sleep 5; done`)
relaunches us. **The restart delay is what helps**, not the relaunch — it
lets the upstream rate-limit expire on its own clock instead of being
starved by the 20s fast-phase loop. Strictly protocol-level (survives the
lesson above): only `dataActivityWatch`'s `RestartError{Reason:"data-
activity stuck"}` counts, and only when the session lived less than the
threshold; normal longer-lived stalls and other reasons never increment.

**IPv6 plumbing:** the parser splits dual-stack data into separate
fields — `PushReply.LocalIP6` (a `netip.Prefix` from `ifconfig-ipv6
<addr>/<plen> <peer>`) and `PushReply.RemoteIP6` (the peer side of
that same directive). `LocalIP` always stays IPv4 (from `ifconfig`),
so do NOT test `LocalIP.Is6()` to decide whether to configure the v6
NIC — read `LocalIP6` instead. OpenVPN has no `route-gateway-ipv6`
directive: standard practice is to use `RemoteIP6` as the v6 default
next-hop, so `buildRoutes` synthesises `::/0 → RemoteIP6` whenever
`RemoteIP6` is valid (symmetric to the v4 `route-gateway` path). An
explicit server-pushed `route-ipv6 ::/0` is harmless — gVisor's
first-hit route matching tolerates the duplicate. Without this
synthesis, providers that push only `ifconfig-ipv6` (no `route-ipv6
::/0`) get a v6 NIC address but no way out, which surfaces as
`"connect tcp [...]: no route to host"` on every v6 dial.

### SOCKS5 daemon (`cmd/openvpn2socks/`)

`socks5Server` accepts a `net.Listener` via `Serve(ctx, ln)`
(http.Server pattern) — that exists specifically so integration tests can
bind `127.0.0.1:0` and discover the port. `main.go` uses
`ListenAndServe(ctx)` instead. CONNECT (TCP) + UDP ASSOCIATE are
supported; BIND returns `REP=0x07`. DNS resolution order:
1. **positive cache** (60s TTL, `dnsCacheTTL`) — masks transient
   upstream-resolver flakiness; defensive-copy on get so callers can't
   poison the cache by mutating the returned slice
2. `-dns` override (over the tunnel) — when set, treated as
   authoritative; the public-resolver fallback below is skipped
3. each PUSH_REPLY DNS server (over the tunnel)
4. `publicDNSFallback` (1.1.1.1) over the tunnel — masks a broken
   provider resolver while keeping DNS **inside** the VPN; only runs
   when no `-dns` override is set
5. system resolver, throttled WARN — DNS leaked

**Address-family-aware qtype filter:** `pickQueryTypes(hasV4, hasV6)`
inside `resolver.queryOverTunnel` decides which DNS qtypes to issue
based on the NIC's current address families. AAAA on a v4-only NIC
is suppressed — the response IPs would be discarded by
`filterUsableIPs` before any dial anyway, but the queries still
hit the wire, doubling the DNS load on the (common) ProtonVPN
v4-only configuration. We watched this load contribute directly
to an upstream UDP rate-limit ("UDP-deaf" mode) under browser
workloads. Symmetric for v6-only NICs. Same filter is also unit-
tested as a pure function so the qtype decision is regression-
covered without needing a real netstack.

Cache writes happen on every successful *tunneled* resolution (including
the public-resolver fallback), but **NOT** on system-resolver results —
caching a system-resolved IP could prolong leak windows after the
tunnel recovers. Empty answer slices are ignored on `cacheSet` so a
"no records" answer doesn't masquerade as a hit.

**Per-host connect-burst limit (`connrate.go`):** a token-bucket
limiter keyed on the **destination IP** (NOT `(IP, port)`) rejects
misbehaving clients before they hit the tunnel. Burst=8, refill=2/sec
— healthy browser fan-out (6-8 parallel sockets per page) sails
through; a misbehaving native client bursting 20 CONNECTs to one
host in ~2 seconds gets refused with REP=0x05 after the burst is
drained. The key choice matters: the field-observed Telegram
Desktop pattern split the burst across both :80 and :443 of one
host (12 + 8 conns), so a per-`(IP, port)` limiter let both halves
through. Per-IP catches the aggregate, which is what overloads the
destination server's own rate-limit. Without this, the burst trips
upstream rate-limiting which cascades into `dataHealthWatch`'s
TCP-deaf trigger, and we end up exiting with code 99 because one
bad client poisoned the whole tunnel. Bucket state is GC'd every
30s for any target idle >5min. Pure-Go, no deps; unit-tested via
burst/refill/independence/aggregate-across-ports cases.

**Address-family filter:** `handleConnect` and the UDP relay funnel the
resolver output through `filterUsableIPs(ips, ns.HasIPv4(), ns.HasIPv6())`
before dialing. This is the fast-fail path for providers that don't push
IPv6 (no `ifconfig-ipv6`): without filtering, a v6 candidate goes through
gVisor, eats a route lookup, and returns `ErrHostUnreachable`. Apps then
do happy-eyeballs through *another* SOCKS5 connection, doubling the log
spam. The filter short-circuits to `REP=0x04 host unreachable` (or a
silent drop on UDP) when the tunnel can't carry the requested family, so
clients fall back to v4 inside the same connection.

## Testing approach

- **In-process server simulator** (`internal/session/session_test.go`)
  uses `transport.MemoryPair` to drive both client and a stub server side
  through the same shared channel. Covers handshake, NCP, rekey, RESTART,
  EXIT, AUTH_FAILED, tls-crypt-v2 — all without Docker.
- **Real-server integration tests** (build tag `integration`) live in
  three modules. They share PKI from `test/integration/pki/` (generated
  once by `make pki`). The Docker container also runs `socat` TCP+UDP
  echo on `10.8.0.1:8080` for data-path verification.
- `t.Parallel()` is used in pure-function tests. Tests that drive the
  full session, reach Docker, or grab global resources stay serial.

## Out of scope (by design — don't add)

- Compression (`comp-lzo`, `compress lz4`) — return errors in the parser
- Static-key only mode (no TLS) — TLS+NCP path only
- Legacy CBC+HMAC data channel — AEAD only
- `dev tap` — tun-mode only
- KEY_METHOD 1 — KEY_METHOD 2 only
- `cipher none` **data channel** — the parser *tolerates* the `cipher none`
  directive (drops it; AEAD is negotiated via NCP), but a true null data
  channel is NOT implemented. tls-auth (control channel) IS supported (see
  `internal/tlsauth`).
