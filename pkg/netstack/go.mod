// Module for the gVisor netstack adapter. Kept separate from the root module
// so the core library does not pull gVisor into its dependency graph; users
// who want a userspace TCP/IP stack on top of the tunnel net.Conn import
// this module explicitly.
module github.com/n0madic/go-openvpn/pkg/netstack

go 1.25.0

replace github.com/n0madic/go-openvpn => ../..

require (
	github.com/n0madic/go-openvpn v0.0.0-00010101000000-000000000000
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/time v0.12.0 // indirect
)
