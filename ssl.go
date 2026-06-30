// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/tls"
	"crypto/x509"
)

// Verify modes mirroring OpenSSL::SSL::VERIFY_*.
const (
	VerifyNone             = 0x00
	VerifyPeer             = 0x01
	VerifyFailIfNoPeerCert = 0x02
	VerifyClientOnce       = 0x04
)

// Protocol-version bounds accepted by SSLContext.MinVersion / MaxVersion,
// mapped onto crypto/tls's version constants when lowering.
const (
	TLS1_0 = "TLS1"
	TLS1_1 = "TLS1_1"
	TLS1_2 = "TLS1_2"
	TLS1_3 = "TLS1_3"
)

// SSLContext models the configuration half of OpenSSL::SSL::SSLContext: the
// cipher list, protocol-version bounds, verify mode and trust store. The live
// TLS handshake is a host seam — ToTLSConfig lowers this model to a
// *tls.Config the host drives with crypto/tls.
type SSLContext struct {
	// VerifyMode is one of the Verify* constants.
	VerifyMode int
	// MinVersion / MaxVersion bound the protocol (one of the TLS1_* names);
	// empty means "library default".
	MinVersion string
	MaxVersion string
	// ServerName sets the SNI / verification hostname.
	ServerName string
	// CertStore is the trusted root pool; nil uses the system roots.
	CertStore *x509.CertPool
	// Certificate / PrivateKey are the local identity, if any.
	Certificate *Certificate
	RSAKey      *RSAKey
}

// NewSSLContext returns a context with MRI's defaults (verify peer).
func NewSSLContext() *SSLContext {
	return &SSLContext{VerifyMode: VerifyPeer}
}

// tlsVersion maps a TLS1_* name to the crypto/tls constant.
func tlsVersion(name string) (uint16, error) {
	switch name {
	case "", TLS1_2:
		return tls.VersionTLS12, nil
	case TLS1_0:
		return tls.VersionTLS10, nil
	case TLS1_1:
		return tls.VersionTLS11, nil
	case TLS1_3:
		return tls.VersionTLS13, nil
	default:
		return 0, sslError("unknown TLS version: " + name)
	}
}

// ToTLSConfig lowers the context model to a *tls.Config for the host to drive.
// This is the documented host seam: it builds configuration only and performs
// no handshake.
func (c *SSLContext) ToTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{ServerName: c.ServerName, RootCAs: c.CertStore}
	if c.VerifyMode == VerifyNone {
		cfg.InsecureSkipVerify = true
	}
	minV, err := tlsVersion(c.MinVersion)
	if err != nil {
		return nil, err
	}
	cfg.MinVersion = minV
	if c.MaxVersion != "" {
		maxV, err := tlsVersion(c.MaxVersion)
		if err != nil {
			return nil, err
		}
		cfg.MaxVersion = maxV
	}
	if c.Certificate != nil && c.RSAKey != nil && c.RSAKey.Private != nil {
		cfg.Certificates = []tls.Certificate{{
			Certificate: [][]byte{c.Certificate.ToDER()},
			PrivateKey:  c.RSAKey.Private,
		}}
	}
	return cfg, nil
}
