// Module for the openvpn2socks CLI. Separate from root so gVisor (pulled
// in via the netstack adapter) does not contaminate the core library's
// dependency graph.
module github.com/n0madic/go-openvpn/cmd/openvpn2socks

go 1.25.0

replace (
	github.com/n0madic/go-openvpn => ../..
	github.com/n0madic/go-openvpn/pkg/netstack => ../../pkg/netstack
)

require (
	github.com/n0madic/go-openvpn v0.0.0-00010101000000-000000000000
	github.com/n0madic/go-openvpn/pkg/netstack v0.0.0-00010101000000-000000000000
	golang.org/x/sync v0.20.0
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
