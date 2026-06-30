// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// MRI oracle: OpenSSL::HMAC.hexdigest("SHA256","key","data")
const hmacSHA256KeyData = "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"

func TestHMACHexDigestVector(t *testing.T) {
	got, err := HMACHexDigest("SHA256", []byte("key"), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if got != hmacSHA256KeyData {
		t.Errorf("got %s", got)
	}
}

func TestHMACStreaming(t *testing.T) {
	m, err := NewHMAC([]byte("key"), "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	m.Update([]byte("da")).Update([]byte("ta"))
	if m.HexDigest() != hmacSHA256KeyData {
		t.Errorf("streamed = %s", m.HexDigest())
	}
	raw, err := HMACDigest("SHA256", []byte("key"), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(m.Digest()) != hex.EncodeToString(raw) {
		t.Errorf("digest mismatch")
	}
	if m.Base64Digest() != base64.StdEncoding.EncodeToString(raw) {
		t.Errorf("b64 mismatch")
	}
	m.Reset().Update([]byte("data"))
	if m.HexDigest() != hmacSHA256KeyData {
		t.Errorf("after reset = %s", m.HexDigest())
	}
}

func TestHMACUnknownAlgorithm(t *testing.T) {
	if _, err := NewHMAC([]byte("k"), "BOGUS"); err == nil {
		t.Error("expected error")
	}
	if _, err := HMACDigest("BOGUS", nil, nil); err == nil {
		t.Error("expected error")
	}
	if _, err := HMACHexDigest("BOGUS", nil, nil); err == nil {
		t.Error("expected error")
	}
}
