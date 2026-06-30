// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"os"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRSAParseSignVerify(t *testing.T) {
	key, err := ParseRSA(readFixture(t, "rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !key.IsPrivate() {
		t.Error("expected private key")
	}
	data := []byte("sign me")
	sig, err := key.Sign("SHA256", data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := key.Verify("SHA256", sig, data)
	if err != nil || !ok {
		t.Errorf("verify failed: %v %v", ok, err)
	}
	// Wrong data fails (no error, false result).
	if ok, _ := key.Verify("SHA256", sig, []byte("other")); ok {
		t.Error("expected verify false for tampered data")
	}
	// Public-only key parsed from public_to_pem verifies the same signature.
	pubPEM := key.PublicToPEM()
	pub, err := ParseRSA(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if pub.IsPrivate() {
		t.Error("public key reported private")
	}
	if ok, _ := pub.Verify("SHA256", sig, data); !ok {
		t.Error("public verify failed")
	}
}

func TestRSAParsePublicFixture(t *testing.T) {
	pub, err := ParseRSA(readFixture(t, "rsa_pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if pub.IsPrivate() {
		t.Error("expected public-only")
	}
}

func TestRSAGenerateAndPEMRoundTrip(t *testing.T) {
	key, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := key.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRSA(pem); err != nil {
		t.Errorf("round-trip parse: %v", err)
	}
}

func TestRSAGenerateTooSmall(t *testing.T) {
	// A key size below the minimum makes rsa.GenerateKey error.
	if _, err := GenerateRSA(1); err == nil {
		t.Error("expected error for tiny key size")
	}
}

func TestRSAPublicOnlyToPEMError(t *testing.T) {
	pub, _ := ParseRSA(readFixture(t, "rsa_pub.pem"))
	if _, err := pub.ToPEM(); err == nil {
		t.Error("expected error: no private key")
	}
	if _, err := pub.Sign("SHA256", []byte("x")); err == nil {
		t.Error("expected sign error on public-only key")
	}
}

func TestRSASignUnknownDigest(t *testing.T) {
	key, _ := ParseRSA(readFixture(t, "rsa.pem"))
	if _, err := key.Sign("MD5", []byte("x")); err == nil {
		t.Error("expected unsupported-digest error")
	}
	if _, err := key.Verify("MD5", nil, nil); err == nil {
		t.Error("expected unsupported-digest error")
	}
}

func TestRSAParsePKCS8AndPKCS1Public(t *testing.T) {
	// PKCS#8 private key.
	k8, err := ParseRSA(readFixture(t, "rsa_pkcs8.pem"))
	if err != nil || !k8.IsPrivate() {
		t.Fatalf("pkcs8 parse: %v", err)
	}
	// PKCS#1 (RSA PUBLIC KEY) public key.
	p1, err := ParseRSA(readFixture(t, "rsa_pub_pkcs1.pem"))
	if err != nil || p1.IsPrivate() {
		t.Fatalf("pkcs1 public parse: %v", err)
	}
}

func TestRSAParseWrongKeyTypes(t *testing.T) {
	// EC key in PKCS#8 parsed as RSA → "PKCS#8 key is not RSA".
	if _, err := ParseRSA(readFixture(t, "ec_pkcs8.pem")); err == nil {
		t.Error("expected PKCS#8-not-RSA error")
	}
	// EC public key (PKIX) parsed as RSA → "PKIX key is not RSA".
	if _, err := ParseRSA(readFixture(t, "ec_pub.pem")); err == nil {
		t.Error("expected PKIX-not-RSA error")
	}
}

func TestRSAParseErrors(t *testing.T) {
	if _, err := ParseRSA([]byte("not pem")); err == nil {
		t.Error("expected error")
	}
	// Valid PEM block but EC key, parsed as RSA → error.
	if _, err := ParseRSA(readFixture(t, "ec.pem")); err == nil {
		t.Error("expected error parsing EC pem as RSA")
	}
}

func TestRSASignDigestVariants(t *testing.T) {
	key, _ := ParseRSA(readFixture(t, "rsa.pem"))
	for _, alg := range []string{"SHA1", "SHA384", "SHA512"} {
		sig, err := key.Sign(alg, []byte("data"))
		if err != nil {
			t.Fatalf("%s sign: %v", alg, err)
		}
		if ok, _ := key.Verify(alg, sig, []byte("data")); !ok {
			t.Errorf("%s verify failed", alg)
		}
	}
}

func TestECParseSignVerify(t *testing.T) {
	key, err := ParseEC(readFixture(t, "ec.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !key.IsPrivate() {
		t.Error("expected private EC key")
	}
	data := []byte("ec sign")
	sig, err := key.Sign("SHA256", data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := key.Verify("SHA256", sig, data)
	if err != nil || !ok {
		t.Errorf("ec verify failed: %v %v", ok, err)
	}
	if ok, _ := key.Verify("SHA256", sig, []byte("other")); ok {
		t.Error("expected false for tampered data")
	}
}

func TestECGenerateAndPublicPEM(t *testing.T) {
	key, err := GenerateEC("prime256v1")
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := key.PublicToPEM()
	pub, err := ParseEC(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if pub.IsPrivate() {
		t.Error("expected public-only")
	}
	sig, _ := key.Sign("SHA256", []byte("d"))
	if ok, _ := pub.Verify("SHA256", sig, []byte("d")); !ok {
		t.Error("public EC verify failed")
	}
}

func TestECParsePKCS8AndPKIX(t *testing.T) {
	k8, err := ParseEC(readFixture(t, "ec_pkcs8.pem"))
	if err != nil || !k8.IsPrivate() {
		t.Fatalf("ec pkcs8 parse: %v", err)
	}
	pub, err := ParseEC(readFixture(t, "ec_pub.pem"))
	if err != nil || pub.IsPrivate() {
		t.Fatalf("ec pkix parse: %v", err)
	}
	// RSA PKCS#8 parsed as EC → "PKCS#8 key is not EC".
	if _, err := ParseEC(readFixture(t, "rsa_pkcs8.pem")); err == nil {
		t.Error("expected PKCS#8-not-EC error")
	}
	// RSA PKIX public parsed as EC → not an EC key.
	if _, err := ParseEC(readFixture(t, "rsa_pub.pem")); err == nil {
		t.Error("expected PKIX-not-EC error")
	}
}

func TestECErrors(t *testing.T) {
	if _, err := GenerateEC("bogus-curve"); err == nil {
		t.Error("expected curve error")
	}
	if _, err := ParseEC([]byte("not pem")); err == nil {
		t.Error("expected parse error")
	}
	if _, err := ParseEC(readFixture(t, "rsa.pem")); err == nil {
		t.Error("expected error parsing RSA as EC")
	}
	pub, _ := ParseEC(readFixture(t, "ec.pem"))
	pub.Private = nil
	if _, err := pub.Sign("SHA256", nil); err == nil {
		t.Error("expected sign error on public-only EC")
	}
}

func TestECGenerateCurveAliases(t *testing.T) {
	for _, c := range []string{"P-256", "secp384r1", "secp521r1"} {
		if _, err := GenerateEC(c); err != nil {
			t.Errorf("curve %s: %v", c, err)
		}
	}
}

func TestECSignUnknownDigest(t *testing.T) {
	key, _ := ParseEC(readFixture(t, "ec.pem"))
	if _, err := key.Sign("MD5", nil); err == nil {
		t.Error("expected unsupported-digest error")
	}
	if _, err := key.Verify("MD5", nil, nil); err == nil {
		t.Error("expected unsupported-digest error")
	}
}
