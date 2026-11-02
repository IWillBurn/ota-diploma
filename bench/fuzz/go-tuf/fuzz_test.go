// Coverage-guided fuzzing of go-tuf's trusted-metadata state machine (backlog D5).
//
// The fuzzer mutates the "signed" body of a role, the harness signs it with the key that the
// trusted root delegates to every role, so the input passes the signature check and reaches
// the logic behind it. This models a broken repository or a holder of an online key, the
// same threat model as the structural scenario fuzz-metadata (OTA-PARSE-01); a panic is a
// finding because a long-running updater process dies instead of reporting an error.
//
//	go test -run=^$ -fuzz=^FuzzTimestampSecond$ -fuzztime=300s
package fuzz

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

var (
	signer                 signature.Signer
	rootRaw, tsRaw, snRaw  []byte
	rootBody, tsBody, snBody, tgBody []byte
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func body(raw []byte) []byte {
	var env struct {
		Signed json.RawMessage `json:"signed"`
	}
	must(json.Unmarshal(raw, &env))
	return env.Signed
}

func init() {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) // deterministic corpus
	var err error
	signer, err = signature.LoadSigner(priv, crypto.Hash(0))
	must(err)
	key, err := metadata.KeyFromPublicKey(priv.Public())
	must(err)
	exp := time.Now().AddDate(10, 0, 0).UTC().Truncate(time.Second)

	root := metadata.Root(exp)
	for _, r := range []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		must(root.Signed.AddKey(key, r))
	}
	_, err = root.Sign(signer)
	must(err)
	rootRaw, err = root.ToBytes(false)
	must(err)

	ts := metadata.Timestamp(exp)
	_, err = ts.Sign(signer)
	must(err)
	tsRaw, err = ts.ToBytes(false)
	must(err)

	sn := metadata.Snapshot(exp)
	_, err = sn.Sign(signer)
	must(err)
	snRaw, err = sn.ToBytes(false)
	must(err)

	tg := metadata.Targets(exp)
	_, err = tg.Sign(signer)
	must(err)
	tgRaw, err := tg.ToBytes(false)
	must(err)

	// root version 2 for UpdateRoot
	root.Signed.Version = 2
	root.ClearSignatures()
	_, err = root.Sign(signer)
	must(err)
	root2Raw, err := root.ToBytes(false)
	must(err)
	rootBody, tsBody, snBody, tgBody = body(root2Raw), body(tsRaw), body(snRaw), body(tgRaw)
}

// sign wraps a fuzzed "signed" body into an envelope of role T and signs it; nil if the body
// does not even parse as T (rejected before any signature check, nothing to reach).
func sign[T metadata.Roles](md *metadata.Metadata[T], b []byte) []byte {
	env := append(append([]byte(`{"signatures":[],"signed":`), b...), '}')
	m, err := md.FromBytes(env)
	if err != nil {
		return nil
	}
	if _, err := m.Sign(signer); err != nil {
		return nil
	}
	raw, err := m.ToBytes(false)
	if err != nil {
		return nil
	}
	return raw
}

func trusted(t *testing.T) *trustedmetadata.TrustedMetadata {
	tm, err := trustedmetadata.New(rootRaw)
	if err != nil {
		t.Fatalf("precondition: trusted root: %v", err)
	}
	return tm
}

// first timestamp after the root
func FuzzTimestampFirst(f *testing.F) {
	f.Add(tsBody)
	f.Fuzz(func(t *testing.T, b []byte) {
		if raw := sign(metadata.Timestamp(), b); raw != nil {
			_, _ = trusted(t).UpdateTimestamp(raw)
		}
	})
}

// a new timestamp while one is already trusted: the rollback checks compare the two
// (the v2.4.2 nil dereference at trustedmetadata.go:144 is on this path)
func FuzzTimestampSecond(f *testing.F) {
	f.Add(tsBody)
	f.Fuzz(func(t *testing.T, b []byte) {
		raw := sign(metadata.Timestamp(), b)
		if raw == nil {
			return
		}
		tm := trusted(t)
		if _, err := tm.UpdateTimestamp(tsRaw); err != nil {
			t.Fatalf("precondition: timestamp v1: %v", err)
		}
		_, _ = tm.UpdateTimestamp(raw)
	})
}

// snapshot after a trusted timestamp
func FuzzSnapshot(f *testing.F) {
	f.Add(snBody)
	f.Fuzz(func(t *testing.T, b []byte) {
		raw := sign(metadata.Snapshot(), b)
		if raw == nil {
			return
		}
		tm := trusted(t)
		if _, err := tm.UpdateTimestamp(tsRaw); err != nil {
			t.Fatalf("precondition: timestamp v1: %v", err)
		}
		_, _ = tm.UpdateSnapshot(raw, false)
	})
}

// targets after a trusted timestamp and snapshot
func FuzzTargets(f *testing.F) {
	f.Add(tgBody)
	f.Fuzz(func(t *testing.T, b []byte) {
		raw := sign(metadata.Targets(), b)
		if raw == nil {
			return
		}
		tm := trusted(t)
		if _, err := tm.UpdateTimestamp(tsRaw); err != nil {
			t.Fatalf("precondition: timestamp v1: %v", err)
		}
		if _, err := tm.UpdateSnapshot(snRaw, false); err != nil {
			t.Fatalf("precondition: snapshot v1: %v", err)
		}
		_, _ = tm.UpdateTargets(raw)
	})
}

// root rotation: a new root signed by the old root key
func FuzzRootUpdate(f *testing.F) {
	f.Add(rootBody)
	f.Fuzz(func(t *testing.T, b []byte) {
		if raw := sign(metadata.Root(), b); raw != nil {
			_, _ = trusted(t).UpdateRoot(raw)
		}
	})
}

// unsigned parsing of whole envelopes of every role (the surface before any signature check)
func FuzzParse(f *testing.F) {
	f.Add(rootRaw)
	f.Add(tsRaw)
	f.Add(snRaw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = metadata.Root().FromBytes(raw)
		_, _ = metadata.Timestamp().FromBytes(raw)
		_, _ = metadata.Snapshot().FromBytes(raw)
		_, _ = metadata.Targets().FromBytes(raw)
		_, _ = trustedmetadata.New(raw)
	})
}
