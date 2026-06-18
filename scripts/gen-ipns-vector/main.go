package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ipfs/boxo/ipns"
	"github.com/ipfs/boxo/path"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x42
	}
	skStd := ed25519.NewKeyFromSeed(seed)
	sk, err := ic.UnmarshalEd25519PrivateKey(skStd)
	if err != nil {
		panic(err)
	}
	pid, err := peer.IDFromPublicKey(sk.GetPublic())
	if err != nil {
		panic(err)
	}

	val, err := path.NewPath("/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	if err != nil {
		panic(err)
	}
	eol := time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC)
	seq := uint64(7)
	ttl := time.Hour

	rec, err := ipns.NewRecord(sk, val, seq, eol, ttl)
	if err != nil {
		panic(err)
	}
	b, err := ipns.MarshalRecord(rec)
	if err != nil {
		panic(err)
	}

	name := ipns.NameFromPeer(pid)
	fmt.Printf("NAME_STR=%s\n", name.String())
	fmt.Printf("PEER_B58=%s\n", peer.ToCid(pid).String()) // cid form
	fmt.Printf("PEER_ID=%s\n", pid.String())              // base58btc multihash
	fmt.Printf("VALUE=%s\n", val.String())
	fmt.Printf("SEQ=%d\n", seq)
	fmt.Printf("RECORD_B64=%s\n", base64.StdEncoding.EncodeToString(b))
}
