// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/rand"
	"io"
)

// randReader is the source of randomness; it is a package variable so tests can
// inject a deterministic/failing reader. It defaults to crypto/rand.Reader.
var randReader io.Reader = rand.Reader

// RandomBytes returns n cryptographically secure random bytes, mirroring
// OpenSSL::Random.random_bytes. It errors on a negative length or a read
// failure.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, newError("Random", "negative string size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, newError("Random", err.Error())
	}
	return b, nil
}

// PseudoBytes is MRI's OpenSSL::Random.pseudo_bytes; modern OpenSSL aliases it to
// the secure source, which this package mirrors.
func PseudoBytes(n int) ([]byte, error) { return RandomBytes(n) }
