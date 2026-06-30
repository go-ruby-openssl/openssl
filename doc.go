// Package openssl is a pure-Go (cgo-free) reimplementation of Ruby's OpenSSL
// standard library, built over Go's crypto/* packages instead of linking
// libcrypto.
//
// It mirrors MRI's OpenSSL surface — Digest, HMAC, Cipher (AES CBC/GCM/CTR),
// the PKCS5/KDF derivation functions, Random, ASN.1 DER, BN bignums, X509
// certificates/names, and the RSA/EC PKey types — with byte-for-byte parity to
// MRI wherever Go's crypto allows it (digests, HMAC, AES vectors, PBKDF2/scrypt/
// HKDF vectors, ASN.1 DER, and PEM round-trips).
//
// It is the OpenSSL backend for go-embedded-ruby (rbgo), replacing and extending
// the in-VM openssl.go shim, but it is a standalone, reusable module with no
// dependency on the Ruby runtime.
//
// # Boundary
//
// IN (real crypto, MRI-faithful): Digest, HMAC, Cipher (AES-128/192/256 in
// CBC/GCM/CTR with PKCS7 padding and GCM tag semantics), PKCS5.PBKDF2HMAC,
// KDF.SCrypt, KDF.HKDF, Random, ASN.1 DER encode/decode of the core universal
// types, BN over math/big, X509 certificate/name parse and accessors plus
// self-signed generation, and RSA/EC key parse, generate, sign and verify.
//
// HOST/Go-crypto SEAM: the TLS handshake. SSLContext models the configuration
// (cipher list, protocol version bounds, verify mode) and lowers it to a
// *tls.Config; the live handshake is performed by the host using crypto/tls,
// not by this package.
//
// OUT OF SCOPE: engines, legacy/deprecated ciphers (DES/RC4/Blowfish), full
// X.509 chain path validation beyond what crypto/x509 exposes, PKCS#12, OCSP,
// and the netscape-SPKI / CRL signing machinery.
package openssl
