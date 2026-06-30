// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func TestNameParseToSAndDER(t *testing.T) {
	// MRI: Name.parse("/CN=foo/O=bar").to_s => "/CN=foo/O=bar"
	//      .to_der => 301c310c300a06035504030c03666f6f310c300a060355040a0c03626172
	n, err := ParseName("/CN=foo/O=bar")
	if err != nil {
		t.Fatal(err)
	}
	if n.String() != "/CN=foo/O=bar" {
		t.Errorf("to_s = %s", n.String())
	}
	der, err := n.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	const want = "301c310c300a06035504030c03666f6f310c300a060355040a0c03626172"
	if hex.EncodeToString(der) != want {
		t.Errorf("der = %s", hex.EncodeToString(der))
	}
}

func TestNameAddEntry(t *testing.T) {
	n := &Name{}
	if _, err := n.AddEntry("CN", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.AddEntry("O", "y"); err != nil {
		t.Fatal(err)
	}
	if n.String() != "/CN=x/O=y" {
		t.Errorf("to_s = %s", n.String())
	}
	if _, err := n.AddEntry("BOGUS", "z"); err == nil {
		t.Error("expected error for unknown attribute")
	}
}

func TestNameParseErrors(t *testing.T) {
	for _, bad := range []string{"CN=foo", "/CNfoo", "/ZZ=foo"} {
		if _, err := ParseName(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	// Empty components are skipped.
	n, err := ParseName("/CN=foo//")
	if err != nil || n.String() != "/CN=foo" {
		t.Errorf("empty-component handling: %v %v", n, err)
	}
}

func TestCertificateParseAccessors(t *testing.T) {
	cert, err := ParseCertificate(readFixture(t, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject().String() != "/CN=test.example/O=GoRubyOpenSSL" {
		t.Errorf("subject = %s", cert.Subject().String())
	}
	if cert.Issuer().String() != "/CN=test.example/O=GoRubyOpenSSL" {
		t.Errorf("issuer = %s", cert.Issuer().String())
	}
	if cert.Serial().Cmp(big.NewInt(4242)) != 0 {
		t.Errorf("serial = %s", cert.Serial())
	}
	if cert.Version() != 2 {
		t.Errorf("version = %d", cert.Version())
	}
	if cert.NotBefore().Unix() != 1700000000 {
		t.Errorf("not_before = %d", cert.NotBefore().Unix())
	}
	if cert.NotAfter().Unix() != 1800000000 {
		t.Errorf("not_after = %d", cert.NotAfter().Unix())
	}
	if cert.SignatureAlgorithm() != "sha256WithRSAEncryption" {
		t.Errorf("sig alg = %s", cert.SignatureAlgorithm())
	}
	pk, err := cert.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pk.(*RSAKey); !ok {
		t.Errorf("public key type = %T", pk)
	}
	// PEM/DER round-trip.
	if _, err := ParseCertificate(cert.ToPEM()); err != nil {
		t.Errorf("PEM round-trip: %v", err)
	}
	if _, err := ParseCertificate(cert.ToDER()); err != nil {
		t.Errorf("DER round-trip: %v", err)
	}
}

func TestCertificateECPublicKeyAndSigAlg(t *testing.T) {
	cert, err := ParseCertificate(readFixture(t, "ec_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := cert.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pk.(*ECKey); !ok {
		t.Errorf("expected EC public key, got %T", pk)
	}
	if cert.SignatureAlgorithm() != "ecdsa-with-SHA256" {
		t.Errorf("sig alg = %s", cert.SignatureAlgorithm())
	}
}

func TestCertificateParseErrors(t *testing.T) {
	if _, err := ParseCertificate([]byte("garbage")); err == nil {
		t.Error("expected parse error")
	}
}

func TestCertificateUnknownOIDInName(t *testing.T) {
	// The subject carries an attribute (title, 2.5.4.12) absent from the
	// short-name map, which must render as the raw dotted OID.
	cert, err := ParseCertificate(readFixture(t, "cert_oddoid.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Subject().String(); got != "/CN=x/2.5.4.12=mytitle" {
		t.Errorf("subject with unknown OID = %s", got)
	}
}

func TestCertificateUnsupportedKeyAndSigAlg(t *testing.T) {
	// An Ed25519 certificate: PublicKey returns the unsupported-type error and
	// SignatureAlgorithm falls through to the generic string form.
	cert, err := ParseCertificate(readFixture(t, "ed25519_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.PublicKey(); err == nil {
		t.Error("expected unsupported public key error")
	}
	if cert.SignatureAlgorithm() != "Ed25519" {
		t.Errorf("sig alg = %s", cert.SignatureAlgorithm())
	}
}

func TestCertificateECDSASHA384(t *testing.T) {
	cert, err := ParseCertificate(readFixture(t, "ec_cert_sha384.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if cert.SignatureAlgorithm() != "ecdsa-with-SHA384" {
		t.Errorf("sig alg = %s", cert.SignatureAlgorithm())
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	key, err := ParseRSA(readFixture(t, "rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := ParseName("/CN=selfsigned.example/O=Acme")
	tmpl := CertTemplate{
		Serial:    big.NewInt(99),
		Subject:   subject,
		NotBefore: time.Unix(1700000000, 0),
		NotAfter:  time.Unix(1800000000, 0),
	}
	cert, err := GenerateSelfSigned(key, tmpl, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject().String() != "/CN=selfsigned.example/O=Acme" {
		t.Errorf("subject = %s", cert.Subject().String())
	}
	if cert.Issuer().String() != cert.Subject().String() {
		t.Error("self-signed issuer != subject")
	}
	if cert.Serial().Cmp(big.NewInt(99)) != 0 {
		t.Errorf("serial = %s", cert.Serial())
	}
}

func TestGenerateSelfSignedDefaultsAndExplicitIssuer(t *testing.T) {
	key, _ := ParseRSA(readFixture(t, "rsa.pem"))
	issuer, _ := ParseName("/CN=ca.example")
	// No serial (defaults to 1), no subject, explicit issuer.
	cert, err := GenerateSelfSigned(key, CertTemplate{
		Issuer:    issuer,
		NotBefore: time.Unix(1700000000, 0),
		NotAfter:  time.Unix(1800000000, 0),
	}, "SHA384")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Serial().Cmp(big.NewInt(1)) != 0 {
		t.Errorf("default serial = %s", cert.Serial())
	}
	if cert.SignatureAlgorithm() != "sha384WithRSAEncryption" {
		t.Errorf("sig alg = %s", cert.SignatureAlgorithm())
	}
}

func TestGenerateSelfSignedErrors(t *testing.T) {
	pub, _ := ParseRSA(readFixture(t, "rsa_pub.pem"))
	if _, err := GenerateSelfSigned(pub, CertTemplate{}, "SHA256"); err == nil {
		t.Error("expected error: no private key")
	}
	key, _ := ParseRSA(readFixture(t, "rsa.pem"))
	if _, err := GenerateSelfSigned(key, CertTemplate{}, "MD5"); err == nil {
		t.Error("expected error: unsupported digest")
	}
	// A negative serial makes x509.CreateCertificate fail.
	subject, _ := ParseName("/CN=x")
	if _, err := GenerateSelfSigned(key, CertTemplate{
		Serial:    big.NewInt(-1),
		Subject:   subject,
		NotBefore: time.Unix(1700000000, 0),
		NotAfter:  time.Unix(1800000000, 0),
	}, "SHA256"); err == nil {
		t.Error("expected error: negative serial")
	}
}

func TestSignatureAlgorithmVariants(t *testing.T) {
	key, _ := ParseRSA(readFixture(t, "rsa.pem"))
	subject, _ := ParseName("/CN=x")
	for alg, want := range map[string]string{
		"SHA512": "sha512WithRSAEncryption",
	} {
		cert, err := GenerateSelfSigned(key, CertTemplate{
			Subject:   subject,
			NotBefore: time.Unix(1700000000, 0),
			NotAfter:  time.Unix(1800000000, 0),
		}, alg)
		if err != nil {
			t.Fatal(err)
		}
		if cert.SignatureAlgorithm() != want {
			t.Errorf("%s => %s", alg, cert.SignatureAlgorithm())
		}
	}
}
