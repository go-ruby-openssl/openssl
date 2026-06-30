// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"slices"
	"strings"
)

// digestConstructors maps a canonical (upper-case, dash-stripped) MRI digest
// algorithm name to the crypto/* constructor producing a byte-identical hash.
// These are the algorithms MRI's OpenSSL::Digest exposes that Go's standard
// library implements without cgo.
var digestConstructors = map[string]func() hash.Hash{
	"MD5":    md5.New,
	"SHA1":   sha1.New,
	"SHA224": sha256.New224,
	"SHA256": sha256.New,
	"SHA384": sha512.New384,
	"SHA512": sha512.New,
}

// DigestAlgorithms returns the supported algorithm names (canonical spelling),
// sorted, so callers can enumerate the surface deterministically.
func DigestAlgorithms() []string {
	names := make([]string, 0, len(digestConstructors))
	for k := range digestConstructors {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

// canonDigestName normalises an algorithm name as MRI's OpenSSL::Digest.new
// does: case-insensitive and tolerant of the dashed spellings ("SHA-256").
func canonDigestName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", ""))
}

// newHashByName returns a fresh hash.Hash for an MRI algorithm name, or an
// error when the name is unknown (matching MRI's "Unsupported digest algorithm").
func newHashByName(name string) (hash.Hash, error) {
	if ctor, ok := digestConstructors[canonDigestName(name)]; ok {
		return ctor(), nil
	}
	return nil, digestError("Unsupported digest algorithm (" + name + ").")
}

// Digest is a running message digest, mirroring OpenSSL::Digest. Create one
// with NewDigest("SHA256") (or the algorithm helpers), feed it with Update, and
// read the running state with Digest/HexDigest/Base64Digest without consuming it.
type Digest struct {
	name string
	h    hash.Hash
}

// NewDigest builds a running Digest for the named algorithm, optionally seeding
// it with initial data (MRI's optional second argument). It returns an error
// for an unknown algorithm.
func NewDigest(name string, seed ...[]byte) (*Digest, error) {
	h, err := newHashByName(name)
	if err != nil {
		return nil, err
	}
	d := &Digest{name: canonDigestName(name), h: h}
	for _, s := range seed {
		d.h.Write(s)
	}
	return d, nil
}

// Name returns the canonical algorithm name (e.g. "SHA256").
func (d *Digest) Name() string { return d.name }

// Update appends data to the running digest and returns the receiver so calls
// chain (mirroring d << a << b and #update).
func (d *Digest) Update(data []byte) *Digest {
	d.h.Write(data)
	return d
}

// Reset discards the accumulated state, returning the digest to its initial
// condition.
func (d *Digest) Reset() *Digest {
	d.h.Reset()
	return d
}

// Digest returns the binary digest of the data accumulated so far, without
// consuming the running state (matching MRI).
func (d *Digest) Digest() []byte { return d.h.Sum(nil) }

// HexDigest returns the lower-case hex encoding of Digest.
func (d *Digest) HexDigest() string { return hex.EncodeToString(d.h.Sum(nil)) }

// Base64Digest returns the standard-base64 encoding of Digest.
func (d *Digest) Base64Digest() string {
	return base64.StdEncoding.EncodeToString(d.h.Sum(nil))
}

// DigestLength returns the digest output size in bytes (#digest_length).
func (d *Digest) DigestLength() int { return d.h.Size() }

// BlockLength returns the algorithm's internal block size in bytes
// (#block_length).
func (d *Digest) BlockLength() int { return d.h.BlockSize() }

// DigestBytes is the one-shot OpenSSL::Digest.digest(name, data): the binary
// digest of data under the named algorithm.
func DigestBytes(name string, data []byte) ([]byte, error) {
	h, err := newHashByName(name)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// HexDigest is the one-shot OpenSSL::Digest.hexdigest(name, data).
func HexDigest(name string, data []byte) (string, error) {
	b, err := DigestBytes(name, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Base64Digest is the one-shot OpenSSL::Digest.base64digest(name, data).
func Base64Digest(name string, data []byte) (string, error) {
	b, err := DigestBytes(name, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
