# Integration tests against a real OpenVPN server

These tests run the `go-openvpn` client against an actual `openvpn` process
inside Docker. They exist to catch wire-protocol bugs that our in-process
simulator can't (since the simulator only implements the same spec we
coded against).

The Docker image pins to `alpine:latest`, which currently ships OpenVPN
**2.6.20**. Earlier in development the same suite was run against OpenVPN
**2.7.3** by changing the Dockerfile to `FROM alpine:edge`.

## Requirements

- Docker / Docker Desktop with `compose` plugin
- Linux: just works
- macOS: Docker Desktop 4.x+ — the embedded Linux VM provides `/dev/net/tun`,
  and the container is granted the device + `NET_ADMIN`
- Go 1.25+ (matches the root `go.mod`)

## One-shot CI flow

```bash
cd test/integration
make all          # pki + up + wait + test + down
```

## Step-by-step (for iteration)

```bash
cd test/integration

make pki          # one-time: generate CA + server/client certs + tls-crypt key
make up           # build + start the OpenVPN container in background
make logs         # tail server logs (Ctrl-C to leave running)
make test         # run go test -tags=integration ./...
make down         # stop + remove the container
make clean        # also wipe ./pki
```

## What's tested

`make test` runs three go-test invocations: this directory (core library),
`pkg/netstack/` (userspace TCP/IP stack), and `cmd/openvpn2socks/` (end-to-end
through the SOCKS5 proxy).

### Core library (`test/integration/`)

| Test | What it proves |
|---|---|
| `TestRealHandshakeUDP` | Hard reset → TLS 1.3 → KEY_METHOD 2 → PUSH_REPLY → EKM derivation all work against the real OpenVPN server |
| `TestRealCipherNegotiation` | NCP: client pins AES-256-GCM / CHACHA20-POLY1305 / AES-128-GCM in turn, server agrees |
| `TestRealPingGateway` | Full data path: AEAD seal/open round-trip via the actual TUN device + container kernel ICMP responder |
| `TestRealExitNotify` | `Client.Close()` makes the server log `CC-EEN exit message received by peer` (explicit-exit-notify is reaching the wire) |
| `TestRealRekey` | `Client.Rekey()` triggers a soft-reset; data continues to flow under the new key-id |

### Userspace netstack adapter (`pkg/netstack/`)

| Test | What it proves |
|---|---|
| `TestRealNetstackTCPEcho` | gVisor TCP/IP stack on top of the tunnel: 30-byte TCP echo round-trip to `10.8.0.1:8080` (in-container `socat` echo) |
| `TestRealNetstackTCPLargeTransfer` | Same path under load: 256 KB blob round-trip exercises window scaling and MTU splitting |

### SOCKS5 proxy CLI (`cmd/openvpn2socks/`)

Spins the whole daemon (Dial → netstack → SOCKS5 listener) against the same
docker server, then drives it from an in-process SOCKS5 client.

| Test | What it proves |
|---|---|
| `TestRealSOCKS5ConnectEcho` | SOCKS5 CONNECT → TCP echo at 10.8.0.1:8080 round-trip |
| `TestRealSOCKS5ConnectRefused` | CONNECT to a closed port returns REP=0x05 (mapped from "connection refused") |
| `TestRealSOCKS5AuthSuccess` | `-socks-auth alice:wonderland` accepts the matching credentials and forwards bytes |
| `TestRealSOCKS5AuthBadCreds` | Same daemon rejects mismatched password during RFC 1929 subnegotiation |
| `TestRealSOCKS5UDPAssociate` | UDP ASSOCIATE: SOCKS5-wrapped datagram → 10.8.0.1:8080 UDP echo → wrapped reply back |

## Server configuration

`server.conf` runs a minimal mTLS + tls-crypt-v1 setup on UDP/1194:

- AEAD only: `data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM`
- TLS 1.3 (via `tls-min-version 1.2` default + Go client requesting 1.3)
- Topology: `subnet`, subnet `10.8.0.0/24`, gateway 10.8.0.1
- `reneg-sec 0` — automatic rekey disabled so tests control timing

## PKI structure

After `make pki`, `./pki/` contains:

```
ca.crt              # ECDSA P-256, self-signed
ca.key
server.crt          # SAN: test-server, localhost, 127.0.0.1
server.key
client.crt          # CN: test-client
client.key
tlscrypt.key        # 256-byte OpenVPN static key
```

Everything is throwaway — `make clean` wipes it; `make pki` regenerates.

## Troubleshooting

**`openvpn` container exits with `Note: Cannot open TUN/TAP dev /dev/net/tun`**

The container couldn't access TUN. On macOS, restart Docker Desktop or check
that the `--device=/dev/net/tun` flag is honoured. On Linux hosts, ensure
the `tun` kernel module is loaded (`modprobe tun`).

**Handshake times out**

`make logs` and look for TLS errors. The most common cause is a mismatched
SNI: the client uses `ServerName: "test-server"`, which must match a SAN in
`server.crt` (it does, by default). If you regenerated the PKI partially,
`make clean && make pki` to start over.

**ICMP test gets no reply**

The container kernel responds to ICMP echo on its own tun IP (10.8.0.1) by
default. If your container is hardened (`sysctl net.ipv4.icmp_echo_ignore_all=1`),
the test will fail. Our Dockerfile leaves the default permissive setting.
