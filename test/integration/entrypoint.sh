#!/bin/sh
# Container entrypoint for the OpenVPN integration server.
#
# Starts both a TCP and a UDP echo on port 8080 (bound to 0.0.0.0 — once tun0
# comes up they are reachable as 10.8.0.1:8080 from VPN clients). These power:
#   - pkg/netstack/ integration tests (TCP CONNECT through the userspace stack)
#   - cmd/openvpn2socks/ integration tests (SOCKS5 CONNECT + UDP ASSOCIATE)
# After backgrounding both, exec OpenVPN as PID 1.
set -e

# TCP echo: each accepted connection is handed to /bin/cat — bytes in,
# bytes out, EOF terminates.
socat -d -d TCP-LISTEN:8080,fork,reuseaddr,bind=0.0.0.0 EXEC:/bin/cat &
TCP_PID=$!
echo "[entrypoint] socat TCP echo on :8080, pid=$TCP_PID"

# UDP echo: socat keeps a single PIPE so each datagram returns to its sender.
# Bound to 10.8.0.1 specifically (the VPN gateway): UDP echo on 0.0.0.0
# returns datagrams from whichever interface fired up last, which is racy
# during container startup. tun0 isn't up at this very moment, so retry in
# the background until the bind succeeds.
(
  while true; do
    if socat -d -d UDP-LISTEN:8080,fork,reuseaddr,bind=10.8.0.1 PIPE 2>&1; then
      break
    fi
    sleep 1
  done
) &
UDP_PID=$!
echo "[entrypoint] socat UDP echo on 10.8.0.1:8080 (retrying until tun0 is up), pid=$UDP_PID"

# Hand over to openvpn (gets PID 1 semantics via exec).
exec openvpn --config /etc/openvpn/server.conf
