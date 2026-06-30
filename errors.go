// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

// Error is the root of the OpenSSL error tree, mirroring MRI's
// OpenSSL::OpenSSLError < StandardError. The per-namespace error types below
// wrap an Error so callers can distinguish them with errors.As while still
// matching the common root with errors.Is.
type Error struct {
	// Kind names the originating namespace (e.g. "Digest", "Cipher",
	// "ASN1", "PKey", "X509", "SSL"); it is empty for a bare OpenSSLError.
	Kind string
	// Msg is the human-readable message.
	Msg string
}

func (e *Error) Error() string {
	if e.Kind == "" {
		return e.Msg
	}
	return e.Kind + "Error: " + e.Msg
}

// newError builds an *Error for namespace kind with the given message.
func newError(kind, msg string) *Error { return &Error{Kind: kind, Msg: msg} }

// The named error constructors mirror MRI's namespaced error classes. Each
// returns an *Error tagged with its namespace so a caller can branch on Kind.
func digestError(msg string) error { return newError("Digest", msg) }
func hmacError(msg string) error   { return newError("HMAC", msg) }
func cipherError(msg string) error { return newError("Cipher", msg) }
func kdfError(msg string) error    { return newError("KDF", msg) }
func asn1Error(msg string) error   { return newError("ASN1", msg) }
func bnError(msg string) error     { return newError("BN", msg) }
func pkeyError(msg string) error   { return newError("PKey", msg) }
func x509Error(msg string) error   { return newError("X509", msg) }
func sslError(msg string) error    { return newError("SSL", msg) }
