// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"encoding/hex"
	"testing"
)

func TestPBKDF2Vector(t *testing.T) {
	// MRI: OpenSSL::PKCS5.pbkdf2_hmac("password","salt",1000,32,SHA256)
	const want = "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"
	got, err := PBKDF2HMAC([]byte("password"), []byte("salt"), 1000, 32, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("pbkdf2 = %s", hex.EncodeToString(got))
	}
}

func TestPBKDF2UnknownAlgorithm(t *testing.T) {
	if _, err := PBKDF2HMAC([]byte("p"), []byte("s"), 1, 16, "BOGUS"); err == nil {
		t.Error("expected error")
	}
}

func TestPBKDF2InvalidKeyLen(t *testing.T) {
	// Negative key length surfaces an error from crypto/pbkdf2.
	if _, err := PBKDF2HMAC([]byte("p"), []byte("s"), 1, -1, "SHA256"); err == nil {
		t.Error("expected error for negative keylen")
	}
}

func TestSCryptVector(t *testing.T) {
	// MRI: OpenSSL::KDF.scrypt("password", salt:"salt", N:1024, r:8, p:1, length:32)
	const want = "16dbc8906763c7f048977a68f9d305f7710e068ca2cd95dab372125bb3f19608"
	got, err := SCrypt([]byte("password"), []byte("salt"), 1024, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("scrypt = %s", hex.EncodeToString(got))
	}
}

func TestSCryptInvalidParams(t *testing.T) {
	// N must be a power of two > 1; 3 is rejected.
	if _, err := SCrypt([]byte("p"), []byte("s"), 3, 8, 1, 32); err == nil {
		t.Error("expected error for invalid N")
	}
}

func TestHKDFVector(t *testing.T) {
	// MRI: OpenSSL::KDF.hkdf("secret", salt:"salt", info:"info", length:32, hash:"SHA256")
	const want = "f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef"
	got, err := HKDF([]byte("secret"), []byte("salt"), []byte("info"), 32, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("hkdf = %s", hex.EncodeToString(got))
	}
}

func TestHKDFUnknownAlgorithm(t *testing.T) {
	if _, err := HKDF([]byte("s"), nil, nil, 16, "BOGUS"); err == nil {
		t.Error("expected error")
	}
}

func TestHKDFTooLong(t *testing.T) {
	// HKDF cannot expand beyond 255*HashLen; an oversized request errors.
	if _, err := HKDF([]byte("s"), []byte("salt"), []byte("info"), 255*32+1, "SHA256"); err == nil {
		t.Error("expected error for oversized output")
	}
}
