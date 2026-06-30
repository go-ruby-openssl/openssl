// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

// Version-identification constants mirroring MRI's OpenSSL module. Because this
// is a pure-Go shim rather than a libcrypto binding, the library banner reports
// the backend rather than a linked OpenSSL build.
const (
	// VERSION is the version of the OpenSSL Ruby binding being emulated.
	VERSION = "4.0.0"
	// OpenSSLVersion is the human-readable backend banner.
	OpenSSLVersion = "go-ruby-openssl pure-Go OpenSSL (crypto/*)"
	// OpenSSLLibraryVersion mirrors OPENSSL_LIBRARY_VERSION.
	OpenSSLLibraryVersion = "go-ruby-openssl pure-Go OpenSSL (crypto/*)"
	// OpenSSLVersionNumber mirrors OPENSSL_VERSION_NUMBER (0 — no libcrypto).
	OpenSSLVersionNumber = 0
	// OpenSSLFIPS reports whether the backend runs in FIPS mode (it does not).
	OpenSSLFIPS = false
)
