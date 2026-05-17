# openvpn2socks

A standalone CLI that dials an OpenVPN 2.6+/2.7 server and exposes the
resulting tunnel as a **local SOCKS5 proxy**. Any application that speaks
SOCKS5 — browsers, `curl`, `ssh -D`, IRC clients, downloaders — can then
route both TCP and UDP through the VPN without a kernel TUN device, without
root, and without changing the system's routing tables.

It is built on top of `github.com/n0madic/go-openvpn` (pure-Go OpenVPN client)
and `github.com/n0madic/go-openvpn/pkg/netstack` (userspace gVisor
TCP/IP stack on top of the tunnel `net.Conn`).

---

## Why?

A traditional OpenVPN client requires root to create a `tun0` interface and
to install routes/firewall rules. That is fine for "VPN the whole machine",
but it is overkill — and often impossible — when you only want **one
application** to use a VPN. Common use cases:

- Send only your browser through a country-specific exit IP.
- Tunnel `ssh` to a host that is only reachable from inside a private network.
- Run regression tests from a specific geographic origin.
- Develop on a laptop without root (`sudo`-less containers, restricted
  laptops, CI runners).
- Run multiple parallel OpenVPN sessions to different providers on the same
  machine without TUN-device name clashes.

`openvpn2socks` makes the VPN session usable from anything that can speak
SOCKS5 — which today is practically every networking tool worth using.

---

## What it does

```
                        ┌─────────────────┐
                        │  Your browser   │
                        │  / curl / ssh   │
                        └────────┬────────┘
                                 │ SOCKS5
                                 ▼
              ┌──────────────────────────────────┐
              │  openvpn2socks (this process)    │
              │  ┌──────────────────────────┐    │
              │  │ SOCKS5 server            │    │
              │  │  • CONNECT  (TCP)        │    │
              │  │  • UDP ASSOCIATE         │    │
              │  └─────────┬────────────────┘    │
              │            │ dial via            │
              │  ┌─────────▼────────────────┐    │
              │  │ gVisor userspace netstack│    │
              │  └─────────┬────────────────┘    │
              │            │ IP packets in/out   │
              │  ┌─────────▼────────────────┐    │
              │  │ go-openvpn client        │    │
              │  │  (tls-crypt, NCP, rekey) │    │
              │  └─────────┬────────────────┘    │
              └────────────┼─────────────────────┘
                           │ encrypted UDP/TCP
                           ▼
                  ┌────────────────┐
                  │ OpenVPN server │
                  └────────────────┘
```

- The OpenVPN client receives IP packets from the gVisor stack and encrypts
  them. Outbound packets exit through the VPN exit IP.
- The gVisor stack is fed only with the data the SOCKS5 server pushes —
  nothing on your machine is forced through it.
- Therefore: apps that don't know about `127.0.0.1:1080` keep using the
  regular network. Apps that target `127.0.0.1:1080` go through the VPN.

---

## Install / build

```bash
# Either go install:
go install github.com/n0madic/go-openvpn/cmd/openvpn2socks@latest

# Or from a local clone:
cd cmd/openvpn2socks && go build .
./openvpn2socks -h
```

The module lives in a separate `go.mod` so that the core `go-openvpn`
library never pulls in gVisor as a dependency.

Go 1.25+ is required (matches the rest of the repository).

---

## Quickstart

### With a `.ovpn` profile (recommended)

Most VPN providers (ProtonVPN, NordVPN, Surfshark, Mullvad with TLS,
self-hosted servers, …) ship a single `.ovpn` config file. Point
`openvpn2socks` at it:

```bash
export OVPN_USER='your-openvpn-username'
export OVPN_PASS='your-openvpn-password'

openvpn2socks -config ~/Downloads/server.ovpn
```

You should see:

```
INFO dialing OpenVPN target=130.195.240.2:1194 network=udp user=… ciphers=[AES-256-GCM]
INFO openvpn session up cipher=AES-256-GCM peer_id=… local_ip=10.x.y.z mtu=1500
INFO VPN up local=10.x.y.z gateway=10.x.y.1 cipher=AES-256-GCM mtu=1500 dns=[10.x.y.1]
INFO SOCKS5 listening addr=127.0.0.1:1080
```

Now route any client through the proxy:

```bash
# TCP
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

# SSH (uses CONNECT)
ssh -o "ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p" user@example.com

# Git over SSH:
GIT_SSH_COMMAND='ssh -o "ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p"' \
  git clone git@github.com:org/repo.git
```

In a browser (Firefox): Network Settings → Manual proxy → SOCKS Host
`127.0.0.1`, port `1080`, SOCKS v5, and tick *"Proxy DNS when using SOCKS
v5"* so domain resolution also flows through the VPN.

### Without a profile — all-flag form

If you don't have a `.ovpn` file and instead have separate PEM blobs and
a tls-crypt key, supply them explicitly:

```bash
openvpn2socks \
  -server vpn.example.com:1194 \
  -network udp \
  -ca /etc/openvpn/ca.crt \
  -cert /etc/openvpn/client.crt \
  -key /etc/openvpn/client.key \
  -tls-crypt /etc/openvpn/ta.key \
  -sni vpn.example.com
```

You can also mix: `-config` is the base, and any of
`-user`, `-pass`, `-sni`, `-port`, `-ciphers` overrides the value parsed
from the profile.

---

## CLI flags

### OpenVPN endpoint

| Flag | Default | Description |
|------|---------|-------------|
| `-config FILE` | — | Path to a `.ovpn` profile. Alternative to manual flags below. |
| `-server HOST:PORT` | — | OpenVPN remote. Required if `-config` is not set. |
| `-network udp\|tcp` | `udp` | Transport. |
| `-user STRING` | `$OVPN_USER` | `auth-user-pass` username. |
| `-pass STRING` | `$OVPN_PASS` | `auth-user-pass` password. |
| `-ca FILE` | — | PEM CA file (used in flag mode, optional in config mode to override). |
| `-cert FILE` | — | PEM client certificate (optional — many providers use user/pass only). |
| `-key FILE` | — | PEM client key (must accompany `-cert`). |
| `-tls-crypt FILE` | — | tls-crypt v1 static key. Required (or its v2 sibling) — modern control-channel encryption is mandatory. |
| `-tls-crypt-v2 FILE` | — | tls-crypt-v2 client bundle. |
| `-ciphers LIST` | `AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM` | Colon-separated AEAD list advertised in `IV_CIPHERS`. The server picks one by NCP. |
| `-port N` | — | When a `.ovpn` lists several `remote` lines, force this port. |
| `-sni NAME` | — | Override TLS ServerName / `verify-x509-name`. |
| `-timeout DUR` | `45s` | OpenVPN handshake timeout. |

### SOCKS5

| Flag | Default | Description |
|------|---------|-------------|
| `-listen ADDR` | `127.0.0.1:1080` | SOCKS5 listen address. Bind to a non-loopback only if you understand the security implications. |
| `-socks-auth user:pass` | — | If set, require RFC 1929 username/password from SOCKS clients. |
| `-idle DUR` | `10m` | Close a proxied TCP connection after this much idle time. `0` disables. |

### DNS

| Flag | Default | Description |
|------|---------|-------------|
| `-dns IP[:port]` | — | DNS server to query through the tunnel. Overrides the server-pushed list. Port defaults to 53. |

### Misc

| Flag | Default | Description |
|------|---------|-------------|
| `-v` | `false` | Verbose logging (slog `Debug`). |

---

## DNS strategy

When a SOCKS5 client sends a domain (ATYP=0x03) instead of an IP literal,
`openvpn2socks` resolves it in this order:

1. **`-dns` override** — if set, send the query over the tunnel UDP to
   that server.
2. **Server-pushed DNS** — each address in `PUSH_REPLY`'s `dhcp-option DNS`
   list is tried in order over the tunnel UDP.
3. **System resolver** — if nothing above produced an answer, the process
   falls back to Go's default resolver. A single warning is logged so you
   know that DNS is now leaking outside the VPN.

The on-the-wire DNS is a minimal RFC 1035 codec embedded in the binary
(no external dependency). A and AAAA records are looked up in parallel
per server; the union of answers is returned. Per-server timeout is 3
seconds.

> ⚠ **No-leak setup.** If you care about hiding your DNS from your ISP,
> verify after start-up that the `VPN up` log line includes a non-empty
> `dns=[…]` list. If it does not, your provider isn't pushing DNS — either
> supply `-dns` explicitly, or accept the system-fallback behaviour.

---

## SOCKS5 features

### CONNECT (TCP, `CMD=0x01`)

Fully supported. The proxy:

1. Resolves the destination if it's a domain (see DNS strategy above).
2. Dials the target TCP address through the userspace netstack.
3. Replies `REP=0x00` with the proxy's bind address.
4. Forwards bytes in both directions until either side closes. Half-closes
   propagate (`CloseWrite()` on the gVisor `*gonet.TCPConn`).
5. Idle deadline (`-idle`) applies separately to each direction.

Errors are mapped to the canonical SOCKS5 reply codes:

| Reply | Condition |
|-------|-----------|
| `0x00` succeeded | TCP three-way completed |
| `0x01` general failure | unknown |
| `0x03` network unreachable | `unreachable`/`no route` in error |
| `0x04` host unreachable | resolution failed, or "host unreachable" |
| `0x05` connection refused | target sent RST |
| `0x06` TTL expired | dial timed out / ctx cancelled |
| `0x07` command not supported | client sent `BIND` |

### UDP ASSOCIATE (`CMD=0x03`)

Implemented per RFC 1928 §7.

The flow:

1. The client opens a TCP control connection and sends `CMD=0x03`.
2. The proxy binds a UDP socket on the same loopback IP as `-listen`
   (ephemeral port).
3. The proxy replies `REP=0x00` with the UDP socket's `BND.ADDR:BND.PORT`.
4. The client sends UDP datagrams to that address, each wrapped in the
   SOCKS5 UDP header:

   ```
   +----+------+------+----------+----------+----------+
   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
   +----+------+------+----------+----------+----------+
   | 2  |  1   |  1   | Variable |    2     | Variable |
   +----+------+------+----------+----------+----------+
   ```
5. The proxy parses each datagram, optionally resolves `DST.ADDR` if it's
   a domain, looks up (or creates) a per-target `*gonet.UDPConn` through
   the netstack, and forwards `DATA`.
6. Reply datagrams from the target are wrapped back in the SOCKS5 UDP
   header (with the original destination encoded so the client can match
   it) and sent to the client.
7. When the TCP control connection closes, all UDP relays for that
   association are torn down.

Limitations:

- **Fragmentation (`FRAG ≠ 0`) is not supported.** Datagrams with non-zero
  `FRAG` are dropped. RFC 1928 explicitly allows this — most clients never
  use fragmentation.
- One client source IP per association. Multiple targets from the same
  client work fine (cached per target).
- Per-target relays close after 60 s of inactivity to avoid resource leaks.

### BIND (`CMD=0x02`)

Not supported. Replied with `REP=0x07`. Active-mode FTP and a couple of
peer-to-peer protocols rely on BIND; they will simply not work through
this proxy.

### Auth methods

- **NoAuth (`0x00`)** — default. Anything connecting to the listener gets
  in. Safe for `127.0.0.1`; risky on a public interface.
- **Username/Password (`0x02`)** — enabled by passing `-socks-auth
  user:pass`. RFC 1929 subnegotiation.
- **GSSAPI (`0x01`)** — not implemented.

---

## Reconnect behaviour

The OpenVPN client is dialed with `Config.AutoReconnect=true`, so:

- Server-initiated `RESTART` (which providers issue on
  scheduled rotations) is absorbed transparently.
- Inbound silence longer than the server-pushed `ping-restart` interval
  (idle UDP NAT timeouts, dead path mid-session, server gone away) is
  surfaced internally as a `*RestartError` and likewise drives the
  reconnect — no more "tunnel just stops carrying traffic" after a
  few minutes of idle.
- The client transmits server-pushed `ping` keepalives so a UDP NAT
  mapping on the path stays warm and the server never times us out.
- Failed DNS-over-tunnel queries fall back to the system resolver for
  *that query only*; the next lookup tries the tunnel again. A
  throttled warning announces the leak.
- The SOCKS5 listener stays bound across reconnects.
- In-flight TCP/UDP proxied connections are force-closed
  unconditionally on every reconnect (the server's view of our
  prior session state is gone even when the tunnel IP looks
  unchanged, so old gVisor endpoints would silently black-hole).
  Caller-side SOCKS5 connections see a closed socket, the same
  semantics as any transient TCP error — most apps retry, and the
  retry binds to whatever the current tunnel IP is.

  The SOCKS5 listener stays bound and accepts new connections
  immediately on the new session.

**Surrender on a stuck tunnel.** When the server-side path is
broken in a way that survives reconnect (a source-port-keyed
rate-limit, an edge blackhole — handshakes succeed but no real
inbound data ever arrives), AutoReconnect would otherwise spin
forever. The daemon defaults `Config.MaxConsecutiveStalls=3`: after
three consecutive AutoReconnect cycles where the freshly-installed
session died within `Config.StableSessionThreshold` (default 60s)
from a "data-activity stuck" `RestartError`, the daemon exits with
code 1. A process supervisor (launchd, systemd, or a shell `until
openvpn2socks ...; do sleep 1; done` loop) should restart it — a
fresh process gets a new kernel UDP socket and a new ephemeral
source port, which typically clears the rate-limit.

There is no manual reconnect command; you can SIGHUP-restart the process
if you want a fresh session.

---

## Verification

### Quick smoke test

```bash
# 1. Baseline: your raw public IP.
curl -s https://ifconfig.me; echo

# 2. Start the proxy in another terminal.
openvpn2socks -config ~/profile.ovpn &

# 3. Same query via SOCKS5 — should return a DIFFERENT IP (the VPN exit).
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me; echo
```

If the two IPs differ — your CONNECT path works end-to-end.

### Verify DNS goes through the tunnel

```bash
# Check pushed DNS:
openvpn2socks -config ~/profile.ovpn -v 2>&1 | grep "VPN up"
# Look for dns=[...]; non-empty means tunneled DNS is in use.

# Or sniff: a working setup shows NO DNS traffic leaving on udp/53 from
# your real interface while curl runs.
sudo tcpdump -ni any 'udp port 53' &
curl --socks5-hostname 127.0.0.1:1080 https://example.org
# Expected: silence (because the DNS query is encapsulated inside the
# OpenVPN UDP stream).
```

### Verify UDP ASSOCIATE

`curl` doesn't use UDP through SOCKS5 directly, but you can test with a
SOCKS5-aware tool. `proxychains4` is one option. A direct end-to-end test:

```bash
# proxychains4 config:
cat > /tmp/pc.conf <<EOF
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
EOF

proxychains4 -f /tmp/pc.conf dig +short example.com
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `error: openvpn dial: context deadline exceeded` during handshake | Wrong credentials, wrong port, or upstream firewall. Try `-v` for the wire trace. |
| `error: openvpn dial: server requested RESTART` immediately after handshake | The server (or your config) explicitly forbids your credentials — happens on free-tier ProtonVPN servers when you use a paid-only suffix in the username. |
| `WARN no DNS over tunnel — falling back to system resolver` | The profile/server did not push any DNS. Supply `-dns 1.1.1.1` (or any DNS reachable from the tunnel) to plug the leak. |
| Browser hangs on every page | "Proxy DNS when using SOCKS v5" is OFF and the system resolver is blocked. Either turn that toggle on or set `-dns`. |
| `REP=0x07` for innocuous URLs | The client tried `BIND`. Some FTP clients fall back automatically; check if the client supports passive mode. |
| `connect failed: i/o timeout` to a host you can reach from the VPN provider's web UI | Your VPN provider may rate-limit or block specific targets. Verify with the provider directly. |

---

## What this tool does NOT do

- It does **not** modify your routing table. Apps that don't speak SOCKS5
  ignore it.
- It does **not** capture WebRTC peer-to-peer traffic — that traffic goes
  through your browser's own UDP sockets, not through SOCKS5.
- It does **not** provide a "kill switch" — if the VPN drops, an application
  that fails over to direct connections will not be intercepted (because
  there is no system-level redirect).
- It does **not** implement SOCKS4/4a, SOCKS5 BIND, or GSSAPI auth.
- It does **not** support `comp-lzo`, `compress lz4`, `tls-auth`, `dev tap`,
  or non-AEAD ciphers (these are policy decisions of the underlying
  go-openvpn library, not implementation bugs).

---

## License & attribution

Same license as the parent `go-openvpn` repository. The userspace TCP/IP
stack is gVisor (`gvisor.dev/gvisor`), Apache 2.0.
