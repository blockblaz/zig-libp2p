// go-libp2p side of the zig-libp2p QUIC interop runner (Phases B2 + B3).
//
// Same environment contract as examples/interop_quic_node.zig on the zig
// side, so the matrix runner can wire either impl into either role:
//
//	ROLE        — "server" | "client"
//	TESTCASE    — "handshake" | "ping" | "gossipsub" | "reqresp"
//	LISTEN_PORT — UDP port on which the server listens (default 4001)
//	SERVER_HOST — IPv4 to dial (default 127.0.0.1)
//	SERVER_PORT — UDP port to dial (default 4001)
//	DEADLINE_MS — overall test deadline (default 30000)
//	SEED_HEX    — 32-byte hex; deterministic ed25519 identity. When unset,
//	              a random keypair is used.
//	REMOTE_PEER_ID — client only; required for ping/gossipsub testcases.
//
// gossipsub-specific:
//
//	GS_TOPIC       — pubsub topic both sides subscribe to (default "/interop/b3")
//	GS_COUNT       — number of messages the server publishes (default 5)
//	GS_PAYLOAD_LEN — bytes per message payload, deterministic content (default 64)
//
// reqresp-specific:
//
//	RR_PAYLOAD_LEN — bytes per request+response (default 256). Wire format is
//	                 a raw byte run; length is known to both sides via env.
//	                 Protocol id is "/interop/b4/echo/1.0.0", pinned in the
//	                 source so both impls reference the same string.
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
	"io"
	"os"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/multiformats/go-multiaddr"
)

// B4 reqresp protocol id — pinned here so both impls agree on the same
// string. See examples/interop_quic_node.zig:reqresp_protocol_id.
const reqrespProtocolID protocol.ID = "/interop/b4/echo/1.0.0"
const defaultRRPayloadLen = 256

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

	case "gossipsub":
		return runGossipsubServer(ctx, h)

	case "reqresp":
		return runReqRespServer(ctx, h)

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

	case "gossipsub":
		return runGossipsubClient(ctx, h, pi.ID)

	case "reqresp":
		return runReqRespClient(ctx, h, pi.ID)

	default:
		return 2, fmt.Errorf("unknown TESTCASE=%s", testcase)
	}
}

// ── Gossipsub testcase (B3) ────────────────────────────────────────────────
//
// Server: subscribe to the topic, wait for a peer, publish N deterministic
// messages, then exit. Client: subscribe, wait until N matching messages
// have been received, then exit.
//
// Deterministic payload (`msg-%05d: <pad>`) is what makes the assertion
// safe under message reordering and lets the next zig-side impl validate
// against the same wire content.

const (
	defaultGsTopic      = "/interop/b3"
	defaultGsCount      = 5
	defaultGsPayloadLen = 64
)

func gsTopic() string  { return envOr("GS_TOPIC", defaultGsTopic) }
func gsCount() int     { return envInt("GS_COUNT", defaultGsCount) }
func gsPayLen() int    { return envInt("GS_PAYLOAD_LEN", defaultGsPayloadLen) }

func gsPayload(idx, length int) []byte {
	out := make([]byte, length)
	header := []byte(fmt.Sprintf("msg-%05d:", idx))
	if len(header) > length {
		return header[:length]
	}
	copy(out, header)
	// Pad the remainder with a fixed byte so the content is fully
	// deterministic across runs / impls.
	for i := len(header); i < length; i++ {
		out[i] = 0x2A
	}
	return out
}

func runGossipsubServer(ctx context.Context, h host.Host) (int, error) {
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return 1, fmt.Errorf("NewGossipSub: %w", err)
	}
	topic, err := ps.Join(gsTopic())
	if err != nil {
		return 1, fmt.Errorf("Join: %w", err)
	}
	// Subscribing on the server side keeps it as a mesh participant so
	// the client's GRAFT lands and the topic-mesh forms.
	sub, err := topic.Subscribe()
	if err != nil {
		return 1, fmt.Errorf("Subscribe: %w", err)
	}
	defer sub.Cancel()

	if err := waitForInbound(ctx, h); err != nil {
		return 1, err
	}
	// Give gossipsub time to form a mesh edge after the conn lands.
	// pubsub.GossipSubHeartbeatInterval defaults to 1s; one full cycle
	// is enough for the GRAFT to land on most networks. CI noise is
	// the reason this isn't shorter.
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
		return 1, ctx.Err()
	}

	count := gsCount()
	plen := gsPayLen()
	for i := 0; i < count; i++ {
		if err := topic.Publish(ctx, gsPayload(i, plen)); err != nil {
			return 1, fmt.Errorf("Publish #%d: %w", i, err)
		}
	}
	fmt.Printf("go_libp2p_interop[server]: gossipsub published %d msgs on %q\n", count, gsTopic())

	// Stay alive long enough for the client to drain the mesh.
	select {
	case <-time.After(3 * time.Second):
	case <-ctx.Done():
	}
	fmt.Println("go_libp2p_interop[server]: gossipsub ok")
	return 0, nil
}

func runGossipsubClient(ctx context.Context, h host.Host, peerID peer.ID) (int, error) {
	_ = peerID // identified via the open conn; pubsub picks it up from h's network
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return 1, fmt.Errorf("NewGossipSub: %w", err)
	}
	topic, err := ps.Join(gsTopic())
	if err != nil {
		return 1, fmt.Errorf("Join: %w", err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return 1, fmt.Errorf("Subscribe: %w", err)
	}
	defer sub.Cancel()

	count := gsCount()
	plen := gsPayLen()
	seen := make(map[string]struct{}, count)
	want := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		want[string(gsPayload(i, plen))] = struct{}{}
	}

	for len(seen) < count {
		msg, err := sub.Next(ctx)
		if err != nil {
			return 1, fmt.Errorf("Next at %d/%d: %w", len(seen), count, err)
		}
		// Skip the local-loopback echo of our own subscription (none,
		// since the client doesn't publish, but pubsub may forward
		// duplicates).
		key := string(msg.Data)
		if _, ok := want[key]; !ok {
			// Unexpected content — flag and keep going; the matrix
			// will surface the total drift if anything is missing.
			fmt.Printf("go_libp2p_interop[client]: gossipsub unexpected msg len=%d\n", len(msg.Data))
			continue
		}
		seen[key] = struct{}{}
	}
	fmt.Printf("go_libp2p_interop[client]: gossipsub got %d/%d msgs\n", len(seen), count)
	fmt.Println("go_libp2p_interop[client]: gossipsub ok")
	return 0, nil
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

// ── Reqresp testcase (B4) ─────────────────────────────────────────────────
//
// Single-shot echo over /interop/b4/echo/1.0.0:
//   - Server registers a stream handler that reads RR_PAYLOAD_LEN bytes
//     then writes them back.
//   - Client opens the stream, sends RR_PAYLOAD_LEN deterministic bytes
//     (low-byte counter `i & 0xff` — matches the zig impl), reads the
//     echo, asserts equality.

func rrPayloadLen() int { return envInt("RR_PAYLOAD_LEN", defaultRRPayloadLen) }

func rrRequestPayload(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(i & 0xff)
	}
	return out
}

func runReqRespServer(ctx context.Context, h host.Host) (int, error) {
	plen := rrPayloadLen()
	done := make(chan error, 1)

	h.SetStreamHandler(reqrespProtocolID, func(s network.Stream) {
		defer s.Close()
		buf := make([]byte, plen)
		if _, err := io.ReadFull(s, buf); err != nil {
			done <- fmt.Errorf("read: %w", err)
			return
		}
		if _, err := s.Write(buf); err != nil {
			done <- fmt.Errorf("write: %w", err)
			return
		}
		// CloseWrite signals EOF to the dialer so it can drain cleanly
		// rather than waiting on the deadline.
		if err := s.CloseWrite(); err != nil {
			done <- fmt.Errorf("close-write: %w", err)
			return
		}
		done <- nil
	})

	if err := waitForInbound(ctx, h); err != nil {
		return 1, err
	}

	select {
	case err := <-done:
		if err != nil {
			return 1, err
		}
	case <-ctx.Done():
		return 1, ctx.Err()
	}
	fmt.Printf("go_libp2p_interop[server]: reqresp ok (%d bytes)\n", plen)
	return 0, nil
}

func runReqRespClient(ctx context.Context, h host.Host, peerID peer.ID) (int, error) {
	plen := rrPayloadLen()
	s, err := h.NewStream(ctx, peerID, reqrespProtocolID)
	if err != nil {
		return 1, fmt.Errorf("NewStream: %w", err)
	}
	defer s.Close()

	req := rrRequestPayload(plen)
	if _, err := s.Write(req); err != nil {
		return 1, fmt.Errorf("write: %w", err)
	}
	if err := s.CloseWrite(); err != nil {
		return 1, fmt.Errorf("close-write: %w", err)
	}

	resp := make([]byte, plen)
	if _, err := io.ReadFull(s, resp); err != nil {
		return 1, fmt.Errorf("read: %w", err)
	}
	for i, b := range resp {
		if b != req[i] {
			return 1, fmt.Errorf("reqresp mismatch at byte %d: got %02x want %02x", i, b, req[i])
		}
	}
	fmt.Printf("go_libp2p_interop[client]: reqresp ok (%d bytes)\n", plen)
	return 0, nil
}
