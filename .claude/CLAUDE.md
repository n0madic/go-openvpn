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
                         (all managed by workers.Manager — named for
                         logs, recovered on panic, cancelled together):
                         readLoop (demuxes incoming by opcode+key-id;
                         on transport-level read error before s.ctx is
                         cancelled, it setCloseErr's a *RestartError and
                         spawns closeAsync so AutoReconnect picks the
                         failure up — without this the socket-died-but-
                         no-watch-fired post-suspend path leaves the
                         tunnel frozen with closeErr=nil),
                         writeLoop + tickLoop (per reliable.Layer, so 2 per
                         key-id), rekeyWatch (rekey trigger watchdog),
                         controlChannelReader (post-handshake RESTART/EXIT/
                         INFO dispatcher), keepaliveLoop (sends PING magic
                         every PushReply.PingInterval), pingRestartWatch
                         (closes session with *RestartError after
                         PushReply.PingRestart of inbound silence),
                         dataActivityWatch (second-tier liveness watchdog
                         that fires when the user is actively sending but
                         no real non-PING inbound data arrives — closes
                         the "tunnel alive but data path stuck" failure
                         mode that pingRestartWatch alone misses),
                         hardResetWatch (closes with *RestartError when
                         the server keeps sending P_CONTROL_HARD_RESET_
                         SERVER_V2 — the server explicitly saying "I
                         lost your session, re-handshake"; typical
                         after-laptop-sleep aftermath),
                         wakeDetectorWatch (notices a wall-clock jump
                         > 10s as evidence the host suspended, forces
                         AutoReconnect immediately instead of waiting
                         on pingRestart to time out on stale keys),
                         statsLogger (periodic packet-flow counter dump).
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
- `Config.AutoReconnect` + `ReconnectMaxAttempts` + `ReconnectMaxInterval`
  — when set, server `RESTART` is absorbed without surfacing to the user.
  When AutoReconnect is on, `Dial` also spawns a background
  `sessionWatcher` goroutine that polls `s.CloseErr()` every
  `sessionWatchPeriod=500ms` and initiates reconnect on a `*RestartError`
  WITHOUT requiring `Tunnel.Read`/`Tunnel.Write` to observe the error.
  This matters: in netstack mode the data path runs through
  `SetIngressHandler` and nobody sits in `Tunnel.Read`. If the host
  suspends, `wakeDetectorWatch` closes the session with a RestartError —
  but with no Read/Write caller to consume the error and no apps writing
  outbound (gVisor TCP has long since timed out, apps haven't retried
  yet), the zombie state persists until manual intervention. The
  watcher is the second pair of hands that picks up RestartError on
  behalf of the netstack-shaped consumer. It exits on terminal errors
  (`ErrAuthFailed`, `ErrReconnectGaveUp`, `ErrClosed`, `ctx.Canceled`)
  or when the session closes for a non-restart reason. `reconnectMu`
  serialises with the `Tunnel.Read/Write` reconnect path so they don't
  step on each other; whichever wins, the other sees `c.session() !=
  failed` and returns nil.
- `Client.RequestRestart(reason string)` — application-level escape hatch
  that forces the current session to close with a `*RestartError` so
  `AutoReconnect` re-dials. Useful for external monitoring / manual
  session refresh / tests. The Tunnel handle survives — blocked Reads
  resume on the new session.
- `Client.OnReconnect(fn func(PushReply)) (detach func())` — register a
  callback fired every time AutoReconnect installs a fresh session.
  **Critical** for anything that caches a tunnel-IP-dependent value:
  gVisor NIC address, bound sockets, host routes. The server assigns a
  *new* `LocalIP` per session (and may also change Gateway / Routes /
  MTU), so failing to refresh those state means post-reconnect packets
  carry the OLD source IP and the server silently drops them — that's
  the long-running "tunnel works for a bit, reconnects, then nothing
  works forever" zombie-loop bug we hit. **Always call the returned
  detach func from your Close path** if the hook's target lifetime is
  shorter than the Client — otherwise the closure keeps that target
  alive past its useful life and may dereference fields that have
  already been torn down. `pkg/netstack/netstack.go::Net.New` registers
  itself via this hook so the gVisor NIC stays in sync automatically;
  `Net.Close` invokes the detach.

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
7. **Keepalive is mandatory and `applyKeepaliveDefaults` fills it when the
   server is silent.** Real servers push `ping N, ping-restart M` and
   expect us to PING every N seconds; if M seconds pass without inbound
   data the server drops us. Several providers (ProtonVPN among them)
   don't push these directives, so we apply defaults
   (`defaultPingInterval=15s` / `defaultPingRestart=60s`) — pushed values
   always win when present. `session.keepaliveLoop` emits the 16-byte
   `proto.PingMagic` (`2a 18 7b f3 64 1e b4 cb 07 ed 2d 0a 98 1f c7 48`,
   per `ping.c::ping_string`) as a regular P_DATA_V2 packet via the
   active slot. Crucially, **PING is suppressed while any outbound data
   has gone out in the last `PingInterval`** — matches upstream OpenVPN's
   `forward.c::process_outgoing_link` which resets `ping_send_interval`
   on every outbound. Loop samples at `interval/4` (≥250ms) so the next
   PING fires promptly once the silence threshold is crossed. PINGs
   themselves count as outbound (loop-local `lastPingSent`); user data
   resets it via `s.lastUserOutbound`. **`lastUserOutbound` is set ONLY
   by `Session.WriteCtx`, NOT by `keepaliveLoop`** — that way
   `dataActivityWatch` (see point 9) keeps treating PINGs as protocol
   overhead, not as user activity. The first nibble (`2`) of PingMagic
   is not a valid IP version, so `pkg/netstack`'s IPv4/IPv6 demux
   drops them naturally; `handleDataIn` also filters them so direct
   `Tunnel.Read` consumers don't see them. `session.pingRestartWatch`
   is the standard OpenVPN watchdog: `now - lastInbound >= ping-restart`
   ⇒ `setCloseErr(&RestartError{...})` ⇒ `Close()` ⇒ AutoReconnect.
   Don't gate the loops on push-reply being non-zero — that's the
   failure mode for providers that don't push. Keepalive `WritePacket`
   errors are non-fatal: log at Debug and `continue` to the next tick.
   Bailing out on the first ENOBUFS would silently mute keepalives for
   the rest of the session (which is the second half of the production
   failure we hunted — see point 8). **`ping_in_total=0` in stats is
   normal, not a bug**: an OpenVPN server's `ping_send_timeout` only
   fires when the server has no outbound, so during active user traffic
   the server never PINGs us — `pingRestartWatch` survives anyway
   because user data updates `lastInbound` (link-options.rst: "ping ...
   or other packet").

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
   liveness.** Servers configured with `keepalive N M` send their own
   PINGs to the client every N seconds. Our `handleDataIn` updates
   `lastInbound` on **any** decrypted inbound packet, *including* the
   PINGs it then filters out. Several failure modes (gVisor link
   endpoint stall, server-side data-path glitch, intermediate device
   silently dropping user traffic) leave PINGs flowing while real
   bytes are silently dropped — `pingRestartWatch` never fires,
   `AutoReconnect` never kicks in, and the user has to restart the
   process manually. `session.dataActivityWatch` is the second-tier
   watchdog: it tracks `lastDataInbound` (non-PING only, updated in
   `handleDataIn`) and `lastUserOutbound` (updated in `Session.WriteCtx`,
   intentionally NOT touched by `keepaliveLoop` which goes direct to
   `transport.WritePacket`). When the user is actively sending
   (`sinceOut < threshold`) but no real data has arrived in
   `DataActivityStuckThreshold` (steady default 60s), it fires
   `RestartError` the same way pingRestartWatch does, surfacing through
   `Read`/`Write` for AutoReconnect.
   **Adaptive two-phase threshold:** for the first
   `DataActivityFastWindow` (default 2 minutes) after session-up, the
   watchdog uses the tighter `DataActivityWarmupFast` (default 10s) /
   `DataActivityStuckThresholdFast` (default 20s) pair; after the
   window elapses it relaxes to the steady values. Rationale: a
   freshly-handshaken session is empirically MUCH more likely to be
   wedged than a steady-state one — post-reconnect failure modes
   include server-side state loss for the prior peer-id,
   source-port-keyed rate limits surviving the reconnect, NAT mapping
   drift, and gVisor TCP zombies retransmitting on the previous
   tunnel IP. Spending the full 60s steady threshold confirming each
   of those (we observed it in a 2026-05-15 prod log: tunnel was wedged
   ~32s when the user gave up and SIGKILL'd) is the difference between
   "tunnel jitters for a few seconds" and "tunnel froze for over a
   minute". The fast values are clamped at runtime to <= steady so
   tests that set explicit short steady values (e.g. 200ms warmup,
   500ms threshold) keep their behaviour without being slowed down by
   the package defaults. The trigger log records `phase=fast/steady`
   plus the elapsed `age` so an operator can tell which side fired.
   **L4-aware liveness — `aggregate` alone is not enough.** Aggregate
   `lastDataInbound` is fed by ANY decrypted non-PING inbound IP
   packet, regardless of L4 family. The user hit 2026-05-15
   19:51-19:55: ~4s after a reconnect the server started selectively
   dropping all TCP responses while UDP DNS replies kept dribbling
   in once a minute or so. From the aggregate channel's perspective
   `sinceIn` reset on every DNS reply, the watchdog never crossed
   the threshold, and the tunnel sat wedged for ~4 minutes until
   the user reached for Ctrl-C. To detect this `Session` also
   tracks `lastDataInboundTCP` / `lastDataInboundUDP` /
   `lastUserOutboundTCP` / `lastUserOutboundUDP`, populated from the
   `sniffL4` helper in `handleDataIn` and `Session.WriteCtx`. The
   pure `decideActivityStall` core checks all three pairs and fires
   on the first match — per-L4 wins over aggregate so the trigger
   log records the most specific cause (`signal=tcp` /
   `signal=udp` / `signal=aggregate`). When an L4 inbound has never
   been observed (e.g. fresh session that's only sent TCP) we use
   the session `age` as the inbound floor, so a never-replied-to
   TCP flow eventually trips the watchdog instead of hiding behind
   the never-touched zero timestamp. The aggregate channel
   intentionally does NOT use that floor — historically it required
   both sides to be observed at least once, preserved to keep
   existing tests stable. `sniffL4` mirrors the parser in
   `pkg/netstack/endpoint.dispatchInbound`; kept private to session
   so the watchdog doesn't drag a netstack dependency into the core
   library.
   Thresholds are configurable via Config; tests can run with
   sub-second windows. Don't unify with pingRestartWatch — the two
   are intentionally independent so we get one of them no matter
   which signal is fake.

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

**Zombie-endpoint cleanup on reconnect (IP-change-conditional):**
existing TCP/UDP gVisor connections that were bound to the OLD
local IP would become zombies when the tunnel IP changes — they
keep retransmitting with the now-invalid src IP, the server drops
those packets, and gVisor's TCP retransmit takes 60-120s to give
up. Apps using those conns see a long stall. To match the OS
kernel's `RTM_CHANGE` behaviour on utun (which fails existing
kernel sockets with `ECONNRESET` the moment the interface address
changes), `Net` tracks every `net.Conn` it hands out via
`DialContext` in an `activeConns sync.Map` (wrapped in a
`trackedConn` that deregisters on `Close`). The OnReconnect hook
calls `applyPushReply` to install the new addresses, then
**unconditionally** force-closes every tracked conn via
`closeActiveOnReconnect` — apps see an immediate error on the next
Read/Write, retry, and the retry's new gVisor endpoint binds to
whatever the current local IP is and registers with the new server
session. Pre-/post-reconnect IPs are logged for diagnostics but no
longer drive a policy decision.

**Why unconditional, not just "IP changed":** an earlier version
preserved active conns when the tunnel IP stayed the same, on the
theory that existing 4-tuples remained valid (server's NAT routes
by IP, not by OpenVPN peer-id). Field evidence killed that theory:
ProtonVPN routinely hands back the same local IP across reconnects
while the server-side OpenVPN session is brand new (different
peer_id), and the previous session's connection state is gone. Even
with the same 4-tuple the server doesn't route packets for our old
conns — gVisor TCP retransmits 60-120s before giving up, apps stall,
and `dataActivityWatch` ends up firing a *second* reconnect a few
seconds later. The visible symptom in the log was a healthy-looking
"reconnect successful" followed by `tcp_current_established>0` with
zero TCP delta_in for a full minute, then another reconnect.
Force-closing everything restores app-level liveness in under a
second. The `trackedConn` wrapper explicitly forwards `CloseWrite()`
and `CloseRead()` so the type assertion in
`socks5_tcp.go::proxy` (`interface{ CloseWrite() error }`) still
matches for TCP-backed conns; for UDP the methods are no-op safe.

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

**Pure observability — no actions.** An earlier iteration added a
"data-path health watchdog" goroutine on top of these counters
that called `cli.RequestRestart` on application-level "TCP-deaf",
"UDP-deaf" or "TCP-RST-storm" signatures, escalating to
`os.Exit(99)` after two consecutive triggers. **It was removed**
because every single failure case we collected on a real
ProtonVPN tunnel turned out to be the watchdog itself creating
the problem:

  - The triggering metric (DNS UDP timeout, transient RST burst
    from a busy browsing session, etc.) reflected an
    application-level hiccup, not a dead tunnel — the OpenVPN
    protocol layer was still flowing, `dataActivityWatch` and
    `pingRestartWatch` weren't firing.
  - The watchdog-requested AutoReconnect changed the tunnel IP.
  - gVisor TCP endpoints bound to the OLD tunnel IP became
    zombies: they kept retransmitting with the now-invalid src
    IP, the server dropped those packets, `ep_in_tcp` looked
    like zero, the watchdog interpreted that as "tcp-deaf" and
    escalated to `os.Exit(99)`.
  - Reference data point: the official OpenVPN CLI client
    against the same endpoint runs stably for hours with no
    such gymnastics. The reconnect machinery built into the
    OpenVPN protocol (`pingRestartWatch`, `dataActivityWatch`,
    `hardResetWatch`, server-pushed RESTART) is the right
    self-healing layer — it operates on protocol-level signals
    that don't false-fire on application transients.

The counters and `statsLoggerLoop` stayed because they're
genuinely useful for diagnosing what's going on. The lesson:
**don't act on application-level metrics when a protocol-level
self-healing layer already exists** — those metrics are inherently
noisier than the underlying protocol's own keepalive/restart
mechanisms, and acting on them turns false signals into real
outages. All three have been observed against a
real ProtonVPN edge under sustained load; mitigation is taking a fresh
session. `healthCooldown=60s` mutes the watchdog after each trigger,
and the snapshot ring is dropped on trigger so the next decision
window evaluates ONLY the new session's data. Decision logic is split
into the pure `decideHealthTrigger(dUDPSent, dEpInUDP, dTCPSent,
dEpInTCP, dTCPRST, window)` so it's unit-tested via table-driven
cases. **Escalation**: consecutive triggers (no clean window
between them) increment a counter; at `healthUnrecoverableLimit=2`
the watchdog calls the `OnUnrecoverable` callback registered via
`Net.SetOnUnrecoverable` — `cmd/openvpn2socks/main.go` wires this
to `os.Exit(99)`. Rationale: ProtonVPN sometimes hands us back the
*same* tunnel IP across `RequestRestart` (we've watched it live,
`local_ip=10.96.0.34` before and after) and the same broken state
follows, so AutoReconnect alone isn't enough — only a full process
relaunch (new kernel UDP socket → new ephemeral source port) breaks
a source-port-keyed rate limit. Don't merge this watchdog into
`session.dataActivityWatch` — that one fires on "user is sending
but no inbound at all"; this one fires on "user is sending UDP/TCP
but the same family comes back as 0" while *other* traffic
(keepalives) keeps `lastDataInbound` fresh and would mask the
failure.

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
- `tls-auth` — modern `tls-crypt` and `tls-crypt-v2` only
- `dev tap` — tun-mode only
- KEY_METHOD 1 — KEY_METHOD 2 only
