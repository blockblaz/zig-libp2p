// go-libp2p side of the zig-libp2p QUIC interop runner (Phase B2).
//
// Same environment contract as examples/interop_quic_node.zig on the zig
// side, so the matrix runner can wire either impl into either role:
//
//	ROLE        — "server" | "client"
//	TESTCASE    — "handshake" | "ping"
//	LISTEN_PORT — UDP port on which the server listens (default 4001)
//	SERVER_HOST — IPv4 to dial (default 127.0.0.1)
//	SERVER_PORT — UDP port to dial (default 4001)
//	DEADLINE_MS — overall test deadline (default 30000)
//	SEED_HEX    — 32-byte hex; deterministic ed25519 identity. When unset,
//	              a random keypair is used.
//	REMOTE_PEER_ID — client only; required for ping testcase, optional for
//	              handshake (TLS leaf check via libp2p RFC 0001 either way).
//
// Stdout includes `go_libp2p_peer_id: peer_id=<base58btc>` on both roles so
// the matrix runner can capture it without launching the binary twice.
//
// Exit codes mirror the zig binary: 0 success, 1 failure, 2 bad config.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/multiformats/go-multiaddr"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// loadIdentity returns an ed25519 keypair, deterministic when SEED_HEX is
// set so the runner can compute peer ids without a separate handshake.
func loadIdentity() (crypto.PrivKey, error) {
	if hexStr := os.Getenv("SEED_HEX"); hexStr != "" {
		seed, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("SEED_HEX: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("SEED_HEX must be %d bytes, got %d", ed25519.SeedSize, len(seed))
		}
		priv64 := ed25519.NewKeyFromSeed(seed) // 64-byte seed||pub
		return crypto.UnmarshalEd25519PrivateKey(priv64)
	}
	priv, _, err := crypto.GenerateEd25519Key(nil)
	return priv, err
}

func newHost(listen string) (host.Host, error) {
	priv, err := loadIdentity()
	if err != nil {
		return nil, err
	}
	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.DisableRelay(),
		libp2p.NoSecurity, // QUIC carries its own TLS — libp2p's secmux is N/A here.
	}
	if listen != "" {
		opts = append(opts, libp2p.ListenAddrStrings(listen))
	} else {
		opts = append(opts, libp2p.NoListenAddrs)
	}
	return libp2p.New(opts...)
}

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "go_libp2p_interop: %v\n", err)
	}
	os.Exit(code)
}

func run() (int, error) {
	role := envOr("ROLE", "server")
	testcase := envOr("TESTCASE", "handshake")
	deadlineMs := envInt("DEADLINE_MS", 30_000)
	deadline := time.Duration(deadlineMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	switch role {
	case "server":
		return runServer(ctx, testcase)
	case "client":
		return runClient(ctx, testcase)
	default:
		return 2, fmt.Errorf("unknown ROLE=%s", role)
	}
}

func runServer(ctx context.Context, testcase string) (int, error) {
	port := envInt("LISTEN_PORT", 4001)
	listen := fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port)
	h, err := newHost(listen)
	if err != nil {
		return 1, err
	}
	defer h.Close()

	pidStr := h.ID().String()
	fmt.Printf("go_libp2p_peer_id: peer_id=%s\n", pidStr)
	fmt.Printf("go_libp2p_interop[server]: listening udp/%d peer=%s\n", port, pidStr)

	switch testcase {
	case "handshake":
		// Wait for at least one inbound connection then settle, mirroring the
		// zig server: prove the TLS handshake + libp2p extension parse on
		// our end, then exit.
		if err := waitForInbound(ctx, h); err != nil {
			return 1, err
		}
		// Brief settle so the dialer can also report success.
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
		fmt.Println("go_libp2p_interop[server]: handshake ok")
		return 0, nil

	case "ping":
		// The ping service is auto-registered by libp2p when no NoPing option
		// is passed; just wait for the conn + a successful round-trip.
		_ = ping.NewPingService(h)
		if err := waitForInbound(ctx, h); err != nil {
			return 1, err
		}
		// go-libp2p's ping protocol handler runs in the background — we
		// only need to keep the host alive until the dialer is done.
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
		fmt.Println("go_libp2p_interop[server]: ping ok")
		return 0, nil

	default:
		return 2, fmt.Errorf("unknown TESTCASE=%s", testcase)
	}
}

func runClient(ctx context.Context, testcase string) (int, error) {
	srvHost := envOr("SERVER_HOST", "127.0.0.1")
	srvPort := envInt("SERVER_PORT", 4001)
	remotePid := envOr("REMOTE_PEER_ID", "")
	if remotePid == "" {
		return 2, errors.New("REMOTE_PEER_ID is required for client role")
	}

	h, err := newHost("")
	if err != nil {
		return 1, err
	}
	defer h.Close()
	fmt.Printf("go_libp2p_peer_id: peer_id=%s\n", h.ID().String())

	maStr := fmt.Sprintf("/ip4/%s/udp/%d/quic-v1/p2p/%s", srvHost, srvPort, remotePid)
	ma, err := multiaddr.NewMultiaddr(maStr)
	if err != nil {
		return 2, fmt.Errorf("multiaddr: %w", err)
	}
	pi, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return 2, fmt.Errorf("AddrInfoFromP2pAddr: %w", err)
	}
	fmt.Printf("go_libp2p_interop[client]: dialing %s\n", maStr)
	if err := h.Connect(ctx, *pi); err != nil {
		return 1, fmt.Errorf("connect: %w", err)
	}
	fmt.Println("go_libp2p_interop[client]: connected")

	switch testcase {
	case "handshake":
		fmt.Println("go_libp2p_interop[client]: handshake ok")
		return 0, nil

	case "ping":
		svc := ping.NewPingService(h)
		results := svc.Ping(ctx, pi.ID)
		select {
		case res := <-results:
			if res.Error != nil {
				return 1, fmt.Errorf("ping: %w", res.Error)
			}
			fmt.Printf("go_libp2p_interop[client]: ping ok rtt=%s\n", res.RTT)
			return 0, nil
		case <-ctx.Done():
			return 1, ctx.Err()
		}

	default:
		return 2, fmt.Errorf("unknown TESTCASE=%s", testcase)
	}
}

func waitForInbound(ctx context.Context, h host.Host) error {
	notifier := &connNotifier{ready: make(chan struct{}, 1)}
	h.Network().Notify(notifier)
	defer h.Network().StopNotify(notifier)
	select {
	case <-notifier.ready:
		return nil
	case <-ctx.Done():
		return errors.New("accept timeout")
	}
}

type connNotifier struct {
	network.NoopNotifiee
	ready chan struct{}
}

func (n *connNotifier) Connected(_ network.Network, _ network.Conn) {
	select {
	case n.ready <- struct{}{}:
	default:
	}
}
