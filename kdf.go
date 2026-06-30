// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"hash"

	"golang.org/x/crypto/scrypt"
)

// PBKDF2HMAC derives a key with PBKDF2 over HMAC, mirroring
// OpenSSL::PKCS5.pbkdf2_hmac / OpenSSL::KDF.pbkdf2_hmac. algorithm names the
// digest (e.g. "SHA256"); iter is the iteration count; keyLen the output size.
func PBKDF2HMAC(password, salt []byte, iter, keyLen int, algorithm string) ([]byte, error) {
	ctor, err := hashCtorByName(algorithm)
	if err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(func() hash.Hash { return ctor() }, string(password), salt, iter, keyLen)
	if err != nil {
		return nil, kdfError(err.Error())
	}
	return key, nil
}

// SCrypt derives a key with scrypt, mirroring OpenSSL::KDF.scrypt. N is the CPU/
// memory cost (a power of two), r the block size, p parallelism, keyLen output.
func SCrypt(password, salt []byte, n, r, p, keyLen int) ([]byte, error) {
	key, err := scrypt.Key(password, salt, n, r, p, keyLen)
	if err != nil {
		return nil, kdfError(err.Error())
	}
	return key, nil
}

// HKDF derives a key with HKDF (extract-and-expand), mirroring
// OpenSSL::KDF.hkdf. algorithm names the digest; salt and info may be empty.
func HKDF(secret, salt, info []byte, keyLen int, algorithm string) ([]byte, error) {
	ctor, err := hashCtorByName(algorithm)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(func() hash.Hash { return ctor() }, secret, salt, string(info), keyLen)
	if err != nil {
		return nil, kdfError(err.Error())
	}
	return key, nil
}
