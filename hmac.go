// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"hash"
)

// HMAC is a running keyed-hash MAC, mirroring OpenSSL::HMAC. Create one with
// NewHMAC, feed it with Update, and read the running tag with
// Digest/HexDigest/Base64Digest.
type HMAC struct {
	h hash.Hash
}

// hashCtorByName resolves an algorithm name to a hash constructor for HMAC,
// returning an error for an unknown algorithm.
func hashCtorByName(name string) (func() hash.Hash, error) {
	ctor, ok := digestConstructors[canonDigestName(name)]
	if !ok {
		return nil, digestError("Unsupported digest algorithm (" + name + ").")
	}
	return ctor, nil
}

// NewHMAC builds a running HMAC over the named digest algorithm and key.
func NewHMAC(key []byte, algorithm string) (*HMAC, error) {
	ctor, err := hashCtorByName(algorithm)
	if err != nil {
		return nil, err
	}
	return &HMAC{h: hmac.New(ctor, key)}, nil
}

// Update appends data to the running MAC and returns the receiver so calls chain.
func (m *HMAC) Update(data []byte) *HMAC {
	m.h.Write(data)
	return m
}

// Reset discards accumulated data while keeping the key.
func (m *HMAC) Reset() *HMAC {
	m.h.Reset()
	return m
}

// Digest returns the binary MAC of the data accumulated so far.
func (m *HMAC) Digest() []byte { return m.h.Sum(nil) }

// HexDigest returns the lower-case hex encoding of Digest.
func (m *HMAC) HexDigest() string { return hex.EncodeToString(m.h.Sum(nil)) }

// Base64Digest returns the standard-base64 encoding of Digest.
func (m *HMAC) Base64Digest() string {
	return base64.StdEncoding.EncodeToString(m.h.Sum(nil))
}

// HMACDigest is the one-shot OpenSSL::HMAC.digest(algorithm, key, data).
func HMACDigest(algorithm string, key, data []byte) ([]byte, error) {
	m, err := NewHMAC(key, algorithm)
	if err != nil {
		return nil, err
	}
	m.Update(data)
	return m.Digest(), nil
}

// HMACHexDigest is the one-shot OpenSSL::HMAC.hexdigest(algorithm, key, data).
func HMACHexDigest(algorithm string, key, data []byte) (string, error) {
	b, err := HMACDigest(algorithm, key, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
