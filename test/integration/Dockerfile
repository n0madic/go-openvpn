# OpenVPN server for integration tests.
# Pinned to alpine:latest: Alpine stable ships the corresponding mainstream
# OpenVPN 2.6.x release (currently 2.6.20). Earlier in development the suite
# was also verified against OpenVPN 2.7.3 via alpine:edge — switch FROM to
# `alpine:edge` to re-run on the newest line.
FROM alpine:latest

RUN apk add --no-cache openvpn iproute2 socat

EXPOSE 1194/udp 1195/udp 1196/udp

# Entrypoint backgrounds a TCP echo on :8080 (reachable as 10.8.0.1:8080 once
# tun0 is up) for the netstack integration test, then runs openvpn in the
# foreground as PID 1.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
