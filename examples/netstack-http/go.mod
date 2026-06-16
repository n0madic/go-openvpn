// Standalone demo: an HTTP GET via the userspace gVisor netstack on top of
// the OpenVPN tunnel. Kept in its own module so the gVisor dependency only
// propagates to consumers that actually import this example.
module github.com/n0madic/go-openvpn/examples/netstack-http

go 1.26.3

replace (
	github.com/n0madic/go-openvpn => ../..
	github.com/n0madic/go-openvpn/pkg/netstack => ../../pkg/netstack
)

require (
	github.com/n0madic/go-openvpn v0.0.0-00010101000000-000000000000
	github.com/n0madic/go-openvpn/pkg/netstack v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/n0madic/go-tun2net v0.0.0-20260607101155-baecdf85b64d // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260603223238-3694902083d5 // indirect
)
