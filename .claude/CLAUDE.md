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
                         readLoop (demuxes incoming by opcode+key-id),
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
- `Client.RequestRestart(reason string)` — application-level escape hatch
  that forces the current session to close with a `*RestartError` so
  `AutoReconnect` re-dials. Useful for external monitoring / manual
  session refresh / tests. The Tunnel handle survives — blocked Reads
  resume on the new session.
- `Client.OnReconnect(fn func(PushReply))` — register a callback fired
  every time AutoReconnect installs a fresh session. **Critical** for
  anything that caches a tunnel-IP-dependent value: gVisor NIC address,
  bound sockets, host routes. The server assigns a *new* `LocalIP` per
  session (and may also change Gateway / Routes / MTU), so failing to
  refresh those state means post-reconnect packets carry the OLD source
  IP and the server silently drops them — that's the long-running
  "tunnel works for a bit, reconnects, then nothing works forever"
  zombie-loop bug we hit. `pkg/netstack/netstack.go::Net.New` registers
  itself via this hook so the gVisor NIC stays in sync automatically.

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
   `DataActivityStuckThreshold` (default 60s), it fires `RestartError`
   the same way pingRestartWatch does, surfacing through `Read`/`Write`
   for AutoReconnect. Thresholds are configurable via Config so tests
   can run with sub-second windows. Don't unify with pingRestartWatch
   — the two are intentionally independent so we get one of them no
   matter which signal is fake.

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

### gVisor netstack adapter (`pkg/netstack/`)

`Net.DialContext` supports both `tcp[/4/6]` and `udp[/4/6]`. Hosts must be
literal IPs — DNS resolution is the caller's responsibility (see
`cmd/openvpn2socks/resolver.go` for tunneled-UDP DNS). The `endpoint`
inside is a `stack.LinkEndpoint` that pumps IP packets between the gVisor
stack and the tunnel `net.Conn` without any link-layer header
(ARPHardwareNone, MaxHeaderLength=0).

**Reconnect synchronisation:** the NIC address / routes / MTU are NOT
fixed at construction. `Net.New` registers an `openvpn.Client.OnReconnect`
hook that re-runs `Net.applyPushReply` against every freshly-installed
session's PUSH_REPLY. Without this, the NIC keeps the *first* session's
tunnel IP even after reconnect, so post-reconnect packets carry the old
source IP and the server drops them — there's no protocol-level error
back, just silent black-hole. The hook updates IPv4 + IPv6 addresses
(new before old, no transient unconfigured-NIC window), reinstalls the
route table (`SetRouteTable` replaces, not merges), and refreshes the
endpoint MTU. Existing TCP/UDP gVisor connections bound to the old
address become zombies and time out naturally — client apps retry and
fresh conns bind to the new local IP.

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
supported; BIND returns `REP=0x07`. DNS resolution order: `-dns` override
→ `PUSH_REPLY` DNS via tunnel UDP → system resolver (with a one-time
leak warning).

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
