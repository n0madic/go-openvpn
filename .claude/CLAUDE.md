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
                         (1s→16s exp backoff, 8 retries), ACK piggyback/standalone,
                         in-order delivery to crypto/tls via reliable.Adapter
internal/control         Handshake state machine: HARD_RESET → TLS over
                         reliable.Adapter → KEY_METHOD 2 → PUSH_REQUEST →
                         TLS-EKM key derivation
internal/data            AEAD seal/open, KeySlot (kid+peerID+ciphers+sendPID+replay),
                         sliding-bitmap replay protection
internal/proto           Opcode encoding, packet headers, KEY_METHOD 2 codec,
                         PUSH_REPLY parser, peer-info builder
internal/session         Orchestrator. Goroutines per active session:
                         readLoop (demuxes incoming by opcode+key-id),
                         writeLoop + tickLoop (per reliable.Layer, so 2 per
                         key-id), rekeyWatch (rekey trigger watchdog), and
                         controlChannelReader (post-handshake RESTART/EXIT/
                         INFO dispatcher). Holds per-key-id slot + layer
                         tables for rekey transition windows.
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

### gVisor netstack adapter (`pkg/netstack/`)

`Net.DialContext` supports both `tcp[/4/6]` and `udp[/4/6]`. Hosts must be
literal IPs — DNS resolution is the caller's responsibility (see
`cmd/openvpn2socks/resolver.go` for tunneled-UDP DNS). The `endpoint`
inside is a `stack.LinkEndpoint` that pumps IP packets between the gVisor
stack and the tunnel `net.Conn` without any link-layer header
(ARPHardwareNone, MaxHeaderLength=0).

### SOCKS5 daemon (`cmd/openvpn2socks/`)

`socks5Server` accepts a `net.Listener` via `Serve(ctx, ln)`
(http.Server pattern) — that exists specifically so integration tests can
bind `127.0.0.1:0` and discover the port. `main.go` uses
`ListenAndServe(ctx)` instead. CONNECT (TCP) + UDP ASSOCIATE are
supported; BIND returns `REP=0x07`. DNS resolution order: `-dns` override
→ `PUSH_REPLY` DNS via tunnel UDP → system resolver (with a one-time
leak warning).

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
