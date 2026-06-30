// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"encoding/base64"
	"reflect"
	"testing"
)

// MRI oracle vectors captured from `ruby -ropenssl` (4.0.0):
//
//	OpenSSL::Digest::SHA256.hexdigest("abc") => ba7816bf...
var digestVectors = map[string]string{
	"MD5":    "900150983cd24fb0d6963f7d28e17f72",
	"SHA1":   "a9993e364706816aba3e25717850c26c9cd0d89d",
	"SHA256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"SHA384": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"SHA512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
}

func TestDigestHexVectors(t *testing.T) {
	for name, want := range digestVectors {
		got, err := HexDigest(name, []byte("abc"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s: got %s want %s", name, got, want)
		}
	}
}

func TestDigestDashedAndLowercaseNames(t *testing.T) {
	got, err := HexDigest("sha-256", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if got != digestVectors["SHA256"] {
		t.Errorf("dashed name mismatch: %s", got)
	}
}

func TestDigestStreaming(t *testing.T) {
	d, err := NewDigest("SHA256")
	if err != nil {
		t.Fatal(err)
	}
	d.Update([]byte("a")).Update([]byte("b")).Update([]byte("c"))
	if d.HexDigest() != digestVectors["SHA256"] {
		t.Errorf("streamed hex = %s", d.HexDigest())
	}
	// Digest does not consume the running state.
	if d.HexDigest() != digestVectors["SHA256"] {
		t.Errorf("second read changed: %s", d.HexDigest())
	}
	if d.Name() != "SHA256" {
		t.Errorf("name = %s", d.Name())
	}
	if d.DigestLength() != 32 || d.BlockLength() != 64 {
		t.Errorf("len=%d block=%d", d.DigestLength(), d.BlockLength())
	}
}

func TestDigestSeedAndReset(t *testing.T) {
	d, err := NewDigest("SHA256", []byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	d.Update([]byte("c"))
	if d.HexDigest() != digestVectors["SHA256"] {
		t.Errorf("seeded hex = %s", d.HexDigest())
	}
	d.Reset().Update([]byte("abc"))
	if d.HexDigest() != digestVectors["SHA256"] {
		t.Errorf("after reset = %s", d.HexDigest())
	}
}

func TestDigestBinaryAndBase64(t *testing.T) {
	raw, err := DigestBytes("SHA256", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("raw len %d", len(raw))
	}
	b64, err := Base64Digest("SHA256", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if b64 != base64.StdEncoding.EncodeToString(raw) {
		t.Errorf("b64 mismatch")
	}
	d, _ := NewDigest("SHA256", []byte("abc"))
	if d.Base64Digest() != b64 {
		t.Errorf("instance b64 mismatch")
	}
	if !reflect.DeepEqual(d.Digest(), raw) {
		t.Errorf("instance digest mismatch")
	}
}

func TestDigestUnknownAlgorithm(t *testing.T) {
	if _, err := NewDigest("BOGUS"); err == nil {
		t.Error("expected error for unknown algorithm")
	}
	if _, err := DigestBytes("BOGUS", nil); err == nil {
		t.Error("expected error")
	}
	if _, err := HexDigest("BOGUS", nil); err == nil {
		t.Error("expected error")
	}
	if _, err := Base64Digest("BOGUS", nil); err == nil {
		t.Error("expected error")
	}
}

func TestDigestAlgorithms(t *testing.T) {
	algs := DigestAlgorithms()
	if len(algs) != 6 {
		t.Fatalf("got %d algorithms", len(algs))
	}
	// Sorted, deterministic.
	for i := 1; i < len(algs); i++ {
		if algs[i] < algs[i-1] {
			t.Errorf("not sorted: %v", algs)
		}
	}
}
