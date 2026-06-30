// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"bytes"
	"errors"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 16 {
		t.Errorf("len = %d", len(b))
	}
	// Vanishingly unlikely to be all zero.
	if bytes.Equal(b, make([]byte, 16)) {
		t.Error("random bytes all zero")
	}
	p, err := PseudoBytes(8)
	if err != nil || len(p) != 8 {
		t.Errorf("pseudo bytes = %v %v", p, err)
	}
}

func TestRandomBytesNegative(t *testing.T) {
	if _, err := RandomBytes(-1); err == nil {
		t.Error("expected error for negative size")
	}
}

// failReader always errors, to exercise the read-failure branch.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestRandomBytesReadFailure(t *testing.T) {
	old := randReader
	randReader = failReader{}
	defer func() { randReader = old }()
	if _, err := RandomBytes(8); err == nil {
		t.Error("expected error from failing reader")
	}
}

func TestErrorFormatting(t *testing.T) {
	if got := (&Error{Msg: "root"}).Error(); got != "root" {
		t.Errorf("bare error = %q", got)
	}
	if got := (&Error{Kind: "Cipher", Msg: "bad"}).Error(); got != "CipherError: bad" {
		t.Errorf("kinded error = %q", got)
	}
	// errors.As recovers the concrete type.
	var e *Error
	if !errors.As(cipherError("x"), &e) || e.Kind != "Cipher" {
		t.Error("errors.As on cipherError failed")
	}
	// Every namespaced constructor tags its kind.
	cases := map[string]error{
		"Digest": digestError("x"), "HMAC": hmacError("x"),
		"Cipher": cipherError("x"), "KDF": kdfError("x"),
		"ASN1": asn1Error("x"), "BN": bnError("x"),
		"PKey": pkeyError("x"), "X509": x509Error("x"), "SSL": sslError("x"),
	}
	for kind, err := range cases {
		var ce *Error
		if !errors.As(err, &ce) || ce.Kind != kind {
			t.Errorf("%s constructor wrong kind: %v", kind, err)
		}
	}
}

func TestVersionConstants(t *testing.T) {
	if VERSION != "4.0.0" {
		t.Errorf("VERSION = %s", VERSION)
	}
	if OpenSSLFIPS {
		t.Error("FIPS should be false")
	}
	if OpenSSLVersionNumber != 0 {
		t.Error("version number should be 0")
	}
	_ = OpenSSLVersion
	_ = OpenSSLLibraryVersion
}
