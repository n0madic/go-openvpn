# go-openvpn

Pure-Go OpenVPN 2.6+ client library. User-space, no CGo, no TUN — exposes a
`net.Conn` over which IP packets flow. Designed for integration with userland
TCP/IP stacks (gVisor netstack, Tailscale-style).

## Status

| Capability | Status |
|---|---|
| UDP / TCP transport (16-bit BE length-prefix on TCP) | ✅ |
| Injectable transport (`Config.DialTransport`) — run OpenVPN over a proxy / obfuscation layer / any `net.Conn` | ✅ |
| Modern wire protocol (P_CONTROL_V1, P_ACK_V1, P_DATA_V2, hard/soft reset) | ✅ |
| tls-crypt v1 (AES-256-CTR + HMAC-SHA256 control channel encryption) | ✅ |
| tls-crypt-v2 (per-client wrapped key, P_CONTROL_HARD_RESET_CLIENT_V3) | ✅ |
| Reliability layer (in-order delivery, retransmit, ACKs, MTU chunking) | ✅ |
| Inner TLS 1.2/1.3 with mTLS (crypto/tls) | ✅ |
| KEY_METHOD 2 binary exchange | ✅ |
| Username/password auth (auth-user-pass) | ✅ |
| NCP cipher negotiation via IV_CIPHERS | ✅ |
| AEAD data channel: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305 | ✅ |
| TLS-EKM key derivation (RFC 5705, `EXPORTER-OpenVPN-datakeys`) | ✅ |
| PUSH_REQUEST / PUSH_REPLY parsing | ✅ |
| AUTH_FAILED handling | ✅ |
| Replay protection (sliding bitmap window) | ✅ |
| Rekey trigger detection (time + packet-id ceiling) | ✅ |
| **Automatic soft-reset rekey** (key-id rotation 1→7, transition window) | ✅ |
| `Client.Rekey(ctx)` for manual rekey | ✅ |
| `--explicit-exit-notify` (sends `EXIT\0` on Close so the server cleans up immediately) | ✅ |
| RESTART detection — surfaces as `*RestartError` from `Tunnel.Read/Write` | ✅ |
| `Config.AutoReconnect` — transparently re-dials on server RESTART | ✅ |
| Keepalive: sends server-negotiated `ping`, watches `ping-restart` (silence triggers `*RestartError`, AutoReconnect picks it up) | ✅ |
| gVisor netstack adapter (`pkg/netstack/`) — userspace TCP/IP through the tunnel | ✅ |
| `.ovpn` profile parser (`pkg/ovpn`) — converts standard OpenVPN config files into `*openvpn.Config` | ✅ |
| Real-world tested: connects to ProtonVPN servers (AES-256-GCM, tls-crypt v1, auth-user-pass, no client cert) | ✅ |
| Local SOCKS5 proxy CLI (`cmd/openvpn2socks/`) — CONNECT + UDP ASSOCIATE, tunnel DNS, no root | ✅ |
| Compression (comp-lzo / lz4) | ❌ intentional — modern config (`--compress` rejected) |
| Static-key mode (no TLS) | ❌ intentional — only TLS+NCP path supported |
| Legacy CBC+HMAC data channel | ❌ intentional — AEAD only |

## Usage

```go
import "github.com/n0madic/go-openvpn"

cli, err := openvpn.Dial(ctx, &openvpn.Config{
    Network:    "udp",
    RemoteAddr: "vpn.example:1194",
    TLSConfig: &tls.Config{
        RootCAs:      caPool,
        Certificates: []tls.Certificate{clientCert},
        ServerName:   "vpn.example",
    },
    TLSCryptV1: tlsCryptStaticKeyBytes,
})
if err != nil { return err }
defer cli.Close()

conn := cli.Tunnel()
// conn is a net.Conn — Read returns one IP packet, Write sends one.
```

For a runnable end-to-end demo, see `examples/ovpn-ping/main.go` — loads a
`.ovpn` profile, dials the server, and pings the pushed gateway via the
tunnel.

### Turning the tunnel into a local SOCKS5 proxy

`cmd/openvpn2socks/` is a standalone binary that dials an OpenVPN server
and exposes the tunnel as a local SOCKS5 proxy. Any app that speaks SOCKS5
— browsers, `curl --socks5-hostname`, `ssh -D`, …— can route both TCP and
UDP through the VPN. No kernel TUN device, no root.

```bash
export OVPN_USER='your-openvpn-username'
export OVPN_PASS='your-openvpn-password'
go run ./cmd/openvpn2socks/ -config ~/profile.ovpn

# In another terminal:
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

Full documentation — every flag, the DNS strategy, SOCKS5 feature matrix
(CONNECT + UDP ASSOCIATE), reconnect behaviour, verification recipes,
troubleshooting — is in
[`cmd/openvpn2socks/README.md`](cmd/openvpn2socks/README.md).

### Parsing `.ovpn` files

`pkg/ovpn` turns a standard OpenVPN profile into a ready-to-use `*openvpn.Config`:

```go
import "github.com/n0madic/go-openvpn/pkg/ovpn"

p, err := ovpn.ParseFile("vpn-profile.ovpn", &ovpn.ParseOptions{
    Username: "alice",          // used if file declares `auth-user-pass`
    Password: "s3cret",
    ServerNameOverride: "vpn-name",  // optional SNI when remote is an IP
})
if err != nil { return err }
cli, err := openvpn.Dial(ctx, p.Config)
```

Supports inline blocks (`<ca>`, `<cert>`, `<key>`, `<tls-crypt>`,
`<tls-crypt-v2>`) and external file references resolved relative to the
profile's directory. Multiple `remote` lines are exposed via `p.Remotes`
(`remote-random` is honored; pass `ParseOptions.PickRemote` for custom
selection). Legacy directives that conflict with the library's policy —
`comp-lzo`, `compress lz4`, `tls-auth`, `dev tap`, non-AEAD `cipher` — return
an error rather than silently going wrong; comfort directives
(`persist-key`, `nobind`, …) are accepted as no-ops.

### Userspace TCP/IP via gVisor netstack

`pkg/netstack/` exposes the tunnel `net.Conn` as a userspace gVisor TCP/IP
stack — useful when integrating into wireguard-style tools where a kernel `tun`
interface is not available.

```go
import "github.com/n0madic/go-openvpn/pkg/netstack"

cli, _ := openvpn.Dial(ctx, cfg)
defer cli.Close()

ns, _ := netstack.New(cli)
defer ns.Close()

httpClient := &http.Client{Transport: &http.Transport{DialContext: ns.DialContext}}
resp, _ := httpClient.Get("http://10.8.0.1:8080/")
```

The netstack package lives in its own Go module so the core library does not
pull gVisor into its dependency graph. A runnable CLI demo is at
`examples/netstack-http/`.

### Custom transport (proxy chaining, obfuscation)

By default the library dials the underlying UDP/TCP socket itself. Set
`Config.DialTransport` to run OpenVPN over a transport you control instead —
a proxy tunnel, an obfuscation layer, or any pre-established `net.Conn`:

```go
import (
    "golang.org/x/net/proxy"
    "github.com/n0madic/go-openvpn"
)

dialer, _ := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)

cli, err := openvpn.Dial(ctx, &openvpn.Config{
    Network:    "tcp",
    RemoteAddr: "vpn.example:443",
    TLSConfig:  tlsCfg,
    TLSCryptV1: tlsCryptStaticKeyBytes,
    DialTransport: func(ctx context.Context, network, addr string) (openvpn.Transport, error) {
        c, err := dialer.Dial("tcp", addr) // OpenVPN-over-SOCKS5
        if err != nil { return nil, err }
        return openvpn.NewStreamTransport(c), nil
    },
})
```

`NewStreamTransport` frames packets for a stream `net.Conn` (the OpenVPN
`proto tcp` 16-bit length prefix); `NewDatagramTransport` wraps a datagram
`net.Conn` (one read = one packet). The factory is called once per
(re)connect — it **must return a fresh connection each call** so
`AutoReconnect` can replace a dead transport. `Network`/`RemoteAddr` are
passed through as hints and may be left empty.

## Architecture

```
        USER (Read/Write IP packets)
              ▲
        ┌─────┴──────┐
        │ *tunnel    │  net.Conn — datagram-oriented
        └─────┬──────┘
        ┌─────┴────────────────────────────────────┐
        │ internal/session.Session                 │  orchestrator
        │ ┌─────────────┐    ┌─────────────────┐   │
        │ │ data.Slot   │    │ control.Run /   │   │
        │ │ AEAD seal/  │    │ tls.Conn +      │   │
        │ │ open        │    │ KEY_METHOD 2 +  │   │
        │ │             │    │ TLS-EKM         │   │
        │ └──────┬──────┘    └────────┬────────┘   │
        └────────┼────────────────────┼────────────┘
                 │ P_DATA_V2          │ P_CONTROL_V1
                 ▼                    ▼
              ┌────────────────────────────┐
              │ internal/reliable.Layer    │  retransmit, ack, in-order
              └────────────┬───────────────┘
                           ▼
              ┌────────────────────────────┐
              │ internal/tlscrypt.Wrapper  │  AES-256-CTR + HMAC-SHA256
              └────────────┬───────────────┘
                           ▼
              ┌────────────────────────────┐
              │ internal/transport         │  UDP / TCP-framed
              └────────────────────────────┘
```

## Testing

```bash
go test ./... -race
```

### Unit / simulated E2E (always run)

All layers ship with golden-vector unit tests plus full E2E integration
tests that pair the real client against a custom in-process server simulator
through `transport.MemoryPair`. The session_test exercises:

- AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305 (NCP)
- tls-crypt v1 and tls-crypt-v2 paths
- AUTH_FAILED handling
- Full handshake → AEAD echo round-trip
- ≥6 second loss/reorder soak (10% loss, 50% reorder) on the reliability layer
- One soft-reset rekey cycle with echo before/after
- Three consecutive rekey cycles (key-id rotation 0→1→2→3) with echo through each

### Real-server interop (Docker, `test/integration/`)

```bash
cd test/integration
make all   # pki + up + wait + test + down
```

Brings up an actual OpenVPN server in Docker (`alpine:latest`, currently
OpenVPN 2.6.20; also verified against 2.7.3 via `alpine:edge`) and runs
the client against it. Tests cover: handshake, ICMP echo through
the data channel, NCP cipher pinning for all three AEAD variants, a full
soft-reset rekey cycle with end-to-end ping verification,
explicit-exit-notify (`Close()` triggers the server's
`CC-EEN exit message received` marker), plus two gVisor-netstack tests
that TCP-dial a socat echo on `10.8.0.1:8080` through the tunnel (30-byte
round-trip and 256 KB transfer).

Implementing this against the real binary surfaced and fixed five protocol
quirks that the simulator alone could not catch:

1. Static-key PEM header — OpenVPN emits `Static key V1` (lowercase 'k')
2. tls-crypt SIV: HMAC tag is BOTH the authenticator AND the AES-CTR IV
3. tls-crypt packet-id is 8 bytes (uint32 counter + uint32 net_time), not 4
4. KEY_METHOD 2 always carries username/password fields (empty when unused)
5. AEAD data packets place the tag BEFORE the ciphertext, not at the end

## License

Licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later) — see [`LICENSE`](LICENSE) for the full text.

Practical implications:

- **No warranty.** The software is provided "AS IS"; the authors are not
  liable for any damages arising from its use (sections 15–17 of the
  license).
- **Copyleft including network use.** Any project that distributes a
  modified or unmodified version of this code, or runs it as part of a
  network-accessible service, must make the corresponding source code
  available to its users under the same license (section 13). This
  applies to SaaS / managed-VPN scenarios, not just to distributed
  binaries.
- **Source files carry an SPDX header** (`AGPL-3.0-or-later`) so license
  scanners and downstream packagers can identify the terms without
  reading file-by-file.

If your project's policy is incompatible with copyleft, this code is not
for you — consider a permissively-licensed alternative.
