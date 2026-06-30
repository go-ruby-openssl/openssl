// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestSSLContextDefaults(t *testing.T) {
	ctx := NewSSLContext()
	if ctx.VerifyMode != VerifyPeer {
		t.Errorf("default verify mode = %d", ctx.VerifyMode)
	}
	cfg, err := ctx.ToTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verify peer should not skip verify")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("default min version = %d", cfg.MinVersion)
	}
}

func TestSSLContextVerifyNone(t *testing.T) {
	ctx := NewSSLContext()
	ctx.VerifyMode = VerifyNone
	ctx.ServerName = "example.com"
	ctx.CertStore = x509.NewCertPool()
	cfg, err := ctx.ToTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("verify none should skip verify")
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("server name = %s", cfg.ServerName)
	}
	if cfg.RootCAs == nil {
		t.Error("cert store not propagated")
	}
}

func TestSSLContextVersions(t *testing.T) {
	ctx := NewSSLContext()
	ctx.MinVersion = TLS1_0
	ctx.MaxVersion = TLS1_3
	cfg, err := ctx.ToTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS10 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("versions = %d %d", cfg.MinVersion, cfg.MaxVersion)
	}
	// All version name mappings.
	for name, want := range map[string]uint16{
		TLS1_1: tls.VersionTLS11, TLS1_2: tls.VersionTLS12,
	} {
		v, err := tlsVersion(name)
		if err != nil || v != want {
			t.Errorf("tlsVersion(%s) = %d %v", name, v, err)
		}
	}
}

func TestSSLContextVersionErrors(t *testing.T) {
	ctx := NewSSLContext()
	ctx.MinVersion = "SSLv2"
	if _, err := ctx.ToTLSConfig(); err == nil {
		t.Error("expected min-version error")
	}
	ctx2 := NewSSLContext()
	ctx2.MaxVersion = "SSLv2"
	if _, err := ctx2.ToTLSConfig(); err == nil {
		t.Error("expected max-version error")
	}
}

func TestSSLContextWithIdentity(t *testing.T) {
	key, _ := ParseRSA(readFixture(t, "rsa.pem"))
	cert, _ := ParseCertificate(readFixture(t, "cert.pem"))
	ctx := NewSSLContext()
	ctx.Certificate = cert
	ctx.RSAKey = key
	cfg, err := ctx.ToTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}
