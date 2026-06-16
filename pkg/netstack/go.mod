// Module for the netstack adapter. It is a thin shim that bridges an
// *openvpn.Client to the github.com/n0madic/go-tun2net PacketTunnel interface.
// Kept separate from the root module so the core library does not pull gVisor
// (transitively, via go-tun2net) into its dependency graph; users who want a
// userspace TCP/IP stack on top of the tunnel net.Conn import this module.
module github.com/n0madic/go-openvpn/pkg/netstack

go 1.26.3

replace github.com/n0madic/go-openvpn => ../..

require (
	github.com/n0madic/go-openvpn v0.0.0-00010101000000-000000000000
	github.com/n0madic/go-tun2net v0.0.0-20260607101155-baecdf85b64d
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260603223238-3694902083d5 // indirect
)
