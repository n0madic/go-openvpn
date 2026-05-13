// Standalone demo: an HTTP GET via the userspace gVisor netstack on top of
// the OpenVPN tunnel. Kept in its own module so the gVisor dependency only
// propagates to consumers that actually import this example.
module github.com/n0madic/go-openvpn/examples/netstack-http

go 1.25.0

replace (
	github.com/n0madic/go-openvpn => ../..
	github.com/n0madic/go-openvpn/pkg/netstack => ../../pkg/netstack
)

require (
	github.com/n0madic/go-openvpn v0.0.0-00010101000000-000000000000
	github.com/n0madic/go-openvpn/pkg/netstack v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
