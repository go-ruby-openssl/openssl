// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// RSAKey wraps an *rsa.PrivateKey (or a public-only *rsa.PublicKey), mirroring
// OpenSSL::PKey::RSA. A parsed public key has Private == nil.
type RSAKey struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// GenerateRSA generates an RSA key of the given bit size.
func GenerateRSA(bits int) (*RSAKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, pkeyError(err.Error())
	}
	return &RSAKey{Private: k, Public: &k.PublicKey}, nil
}

// ParseRSA parses an RSA key from PEM (PKCS#1 or PKCS#8 private, or PKCS#1/PKIX
// public), mirroring OpenSSL::PKey::RSA.new(pem).
func ParseRSA(pemBytes []byte) (*RSAKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, pkeyError("not a PEM-encoded key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &RSAKey{Private: k, Public: &k.PublicKey}, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return &RSAKey{Private: rk, Public: &rk.PublicKey}, nil
		}
		return nil, pkeyError("PKCS#8 key is not RSA")
	}
	if pk, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return &RSAKey{Public: pk}, nil
	}
	if pk, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rp, ok := pk.(*rsa.PublicKey); ok {
			return &RSAKey{Public: rp}, nil
		}
		return nil, pkeyError("PKIX key is not RSA")
	}
	return nil, pkeyError("could not parse RSA key")
}

// IsPrivate reports whether the key carries private material (#private?).
func (r *RSAKey) IsPrivate() bool { return r.Private != nil }

// ToPEM returns the PKCS#1 private-key PEM, erroring on a public-only key.
func (r *RSAKey) ToPEM() ([]byte, error) {
	if r.Private == nil {
		return nil, pkeyError("no private key available")
	}
	der := x509.MarshalPKCS1PrivateKey(r.Private)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
}

// PublicToPEM returns the PKIX public-key PEM (#public_to_pem). Marshalling an
// *rsa.PublicKey never fails, so the error is elided.
func (r *RSAKey) PublicToPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(r.Public)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Sign signs data with PKCS#1 v1.5 over the named digest, mirroring
// OpenSSL::PKey::RSA#sign(digest, data).
func (r *RSAKey) Sign(algorithm string, data []byte) ([]byte, error) {
	if r.Private == nil {
		return nil, pkeyError("private key needed to sign")
	}
	h, hashID, err := cryptoHashByName(algorithm)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	// SignPKCS1v15 only fails on a too-short key for the hash; production RSA
	// keys are large enough, so the error path is unreachable here.
	sig, _ := rsa.SignPKCS1v15(rand.Reader, r.Private, hashID, h.Sum(nil))
	return sig, nil
}

// Verify verifies a PKCS#1 v1.5 signature (#verify(digest, sig, data)).
func (r *RSAKey) Verify(algorithm string, sig, data []byte) (bool, error) {
	h, hashID, err := cryptoHashByName(algorithm)
	if err != nil {
		return false, err
	}
	h.Write(data)
	if err := rsa.VerifyPKCS1v15(r.Public, hashID, h.Sum(nil), sig); err != nil {
		return false, nil
	}
	return true, nil
}

// cryptoHashByName maps an MRI digest name to a crypto.Hash and a fresh hash
// for signing.
func cryptoHashByName(name string) (h interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}, id crypto.Hash, err error) {
	switch canonDigestName(name) {
	case "SHA256":
		id = crypto.SHA256
	case "SHA384":
		id = crypto.SHA384
	case "SHA512":
		id = crypto.SHA512
	case "SHA1":
		id = crypto.SHA1
	default:
		return nil, 0, pkeyError("unsupported signature digest (" + name + ")")
	}
	return id.New(), id, nil
}

// ECKey wraps an *ecdsa.PrivateKey (or public-only), mirroring
// OpenSSL::PKey::EC.
type ECKey struct {
	Private *ecdsa.PrivateKey
	Public  *ecdsa.PublicKey
}

// curveByName maps an MRI/OpenSSL curve name to a Go elliptic.Curve.
func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "prime256v1", "P-256", "secp256r1":
		return elliptic.P256(), nil
	case "secp384r1", "P-384":
		return elliptic.P384(), nil
	case "secp521r1", "P-521":
		return elliptic.P521(), nil
	default:
		return nil, pkeyError("unsupported EC curve (" + name + ")")
	}
}

// GenerateEC generates an EC key on the named curve.
func GenerateEC(curveName string) (*ECKey, error) {
	curve, err := curveByName(curveName)
	if err != nil {
		return nil, err
	}
	// ecdsa.GenerateKey only fails for an unknown curve, excluded by curveByName.
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	return &ECKey{Private: k, Public: &k.PublicKey}, nil
}

// ParseEC parses an EC key from PEM (SEC1 or PKCS#8 private, PKIX public).
func ParseEC(pemBytes []byte) (*ECKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, pkeyError("not a PEM-encoded key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return &ECKey{Private: k, Public: &k.PublicKey}, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ek, ok := k.(*ecdsa.PrivateKey); ok {
			return &ECKey{Private: ek, Public: &ek.PublicKey}, nil
		}
		return nil, pkeyError("PKCS#8 key is not EC")
	}
	if pk, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if ep, ok := pk.(*ecdsa.PublicKey); ok {
			return &ECKey{Public: ep}, nil
		}
		return nil, pkeyError("PKIX key is not EC")
	}
	return nil, pkeyError("could not parse EC key")
}

// IsPrivate reports whether the key carries private material.
func (e *ECKey) IsPrivate() bool { return e.Private != nil }

// Sign signs data with ECDSA over the named digest (ASN.1 DER signature).
func (e *ECKey) Sign(algorithm string, data []byte) ([]byte, error) {
	if e.Private == nil {
		return nil, pkeyError("private key needed to sign")
	}
	h, _, err := cryptoHashByName(algorithm)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	// ecdsa.SignASN1 does not fail for a valid private key and hash.
	sig, _ := ecdsa.SignASN1(rand.Reader, e.Private, h.Sum(nil))
	return sig, nil
}

// Verify verifies an ECDSA ASN.1 signature.
func (e *ECKey) Verify(algorithm string, sig, data []byte) (bool, error) {
	h, _, err := cryptoHashByName(algorithm)
	if err != nil {
		return false, err
	}
	h.Write(data)
	return ecdsa.VerifyASN1(e.Public, h.Sum(nil), sig), nil
}

// PublicToPEM returns the PKIX public-key PEM. Marshalling an *ecdsa.PublicKey
// on a supported curve never fails, so the error is elided.
func (e *ECKey) PublicToPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(e.Public)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
