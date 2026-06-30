// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

// nameAttr is one RDN attribute (a short name like "CN" and its value),
// preserving order so the DER matches MRI's input ordering.
type nameAttr struct {
	Type  string
	Value string
}

// Name mirrors OpenSSL::X509::Name: an ordered list of DN attributes.
type Name struct {
	attrs []nameAttr
}

// shortNameToOID maps the DN short names MRI accepts to their OIDs.
var shortNameToOID = map[string]string{
	"CN": "2.5.4.3", "C": "2.5.4.6", "L": "2.5.4.7", "ST": "2.5.4.8",
	"O": "2.5.4.10", "OU": "2.5.4.11", "emailAddress": "1.2.840.113549.1.9.1",
	"DC": "0.9.2342.19200300.100.1.25", "UID": "0.9.2342.19200300.100.1.1",
	"serialNumber": "2.5.4.5", "GN": "2.5.4.42", "SN": "2.5.4.4",
}

// oidToShortName is the reverse map, for rendering parsed certificates.
var oidToShortName = func() map[string]string {
	m := make(map[string]string, len(shortNameToOID))
	for k, v := range shortNameToOID {
		m[v] = k
	}
	return m
}()

// ParseName parses a slash-delimited DN ("/CN=foo/O=bar"), mirroring
// OpenSSL::X509::Name.parse.
func ParseName(s string) (*Name, error) {
	if !strings.HasPrefix(s, "/") {
		return nil, x509Error("malformed DN: must start with '/'")
	}
	n := &Name{}
	for _, part := range strings.Split(s[1:], "/") {
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, x509Error("malformed DN component: " + part)
		}
		typ := part[:eq]
		if _, ok := shortNameToOID[typ]; !ok {
			return nil, x509Error("unknown DN attribute: " + typ)
		}
		n.attrs = append(n.attrs, nameAttr{Type: typ, Value: part[eq+1:]})
	}
	return n, nil
}

// AddEntry appends a DN attribute, returning the receiver for chaining.
func (n *Name) AddEntry(typ, value string) (*Name, error) {
	if _, ok := shortNameToOID[typ]; !ok {
		return nil, x509Error("unknown DN attribute: " + typ)
	}
	n.attrs = append(n.attrs, nameAttr{Type: typ, Value: value})
	return n, nil
}

// String renders the slash-delimited form (#to_s).
func (n *Name) String() string {
	var b strings.Builder
	for _, a := range n.attrs {
		b.WriteByte('/')
		b.WriteString(a.Type)
		b.WriteByte('=')
		b.WriteString(a.Value)
	}
	return b.String()
}

// ToDER encodes the Name to DER as a SEQUENCE of SET of SEQUENCE{OID,UTF8String},
// preserving attribute order and using UTF8String, matching MRI byte-for-byte.
func (n *Name) ToDER() ([]byte, error) {
	rdns := make([]*ASN1Value, 0, len(n.attrs))
	for _, a := range n.attrs {
		oid := shortNameToOID[a.Type]
		inner := Sequence(ObjectID(oid), UTF8String(a.Value))
		rdns = append(rdns, Set(inner))
	}
	return Sequence(rdns...).ToDER()
}

// toPKIX builds a pkix.Name for certificate generation, preserving order via
// ExtraNames.
func (n *Name) toPKIX() pkix.Name {
	var pk pkix.Name
	for _, a := range n.attrs {
		oid := mustOID(shortNameToOID[a.Type])
		pk.ExtraNames = append(pk.ExtraNames, pkix.AttributeTypeAndValue{Type: oid, Value: a.Value})
	}
	return pk
}

// mustOID parses a dotted OID into an asn1.ObjectIdentifier.
func mustOID(s string) []int {
	arcs, _ := parseOIDArcs(s)
	return arcs
}

// nameFromPKIX renders a pkix.Name back to a *Name using the short-name map,
// for parsed certificates.
func nameFromPKIX(p pkix.Name) *Name {
	n := &Name{}
	for _, rdn := range p.Names {
		oid := rdn.Type.String()
		short, ok := oidToShortName[oid]
		if !ok {
			short = oid
		}
		val, _ := rdn.Value.(string)
		n.attrs = append(n.attrs, nameAttr{Type: short, Value: val})
	}
	return n
}

// Certificate mirrors OpenSSL::X509::Certificate: a parsed or freshly-built
// X.509 certificate.
type Certificate struct {
	cert *x509.Certificate
}

// ParseCertificate parses a PEM- or DER-encoded certificate.
func ParseCertificate(data []byte) (*Certificate, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, x509Error(err.Error())
	}
	return &Certificate{cert: c}, nil
}

// Subject returns the certificate subject as a *Name.
func (c *Certificate) Subject() *Name { return nameFromPKIX(c.cert.Subject) }

// Issuer returns the certificate issuer as a *Name.
func (c *Certificate) Issuer() *Name { return nameFromPKIX(c.cert.Issuer) }

// Serial returns the serial number.
func (c *Certificate) Serial() *big.Int { return new(big.Int).Set(c.cert.SerialNumber) }

// Version returns the X.509 version field (#version): 0-based, so a v3 cert
// reports 2, matching MRI.
func (c *Certificate) Version() int { return c.cert.Version - 1 }

// NotBefore returns the validity start.
func (c *Certificate) NotBefore() time.Time { return c.cert.NotBefore }

// NotAfter returns the validity end.
func (c *Certificate) NotAfter() time.Time { return c.cert.NotAfter }

// PublicKey returns the certificate's RSA or EC public key wrapped in the
// matching PKey type, or an error for an unsupported key type.
func (c *Certificate) PublicKey() (any, error) {
	switch pk := c.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return &RSAKey{Public: pk}, nil
	case *ecdsa.PublicKey:
		return &ECKey{Public: pk}, nil
	default:
		return nil, x509Error("unsupported certificate public key type")
	}
}

// SignatureAlgorithm returns the OpenSSL-style signature algorithm name
// (e.g. "sha256WithRSAEncryption").
func (c *Certificate) SignatureAlgorithm() string {
	switch c.cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		return "sha256WithRSAEncryption"
	case x509.SHA384WithRSA:
		return "sha384WithRSAEncryption"
	case x509.SHA512WithRSA:
		return "sha512WithRSAEncryption"
	case x509.ECDSAWithSHA256:
		return "ecdsa-with-SHA256"
	case x509.ECDSAWithSHA384:
		return "ecdsa-with-SHA384"
	default:
		return c.cert.SignatureAlgorithm.String()
	}
}

// ToPEM returns the PEM encoding of the certificate.
func (c *Certificate) ToPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// ToDER returns the DER encoding of the certificate.
func (c *Certificate) ToDER() []byte { return c.cert.Raw }

// CertTemplate carries the fields for generating a self-signed certificate,
// mirroring the OpenSSL::X509::Certificate setters used before #sign.
type CertTemplate struct {
	Serial    *big.Int
	Subject   *Name
	Issuer    *Name
	NotBefore time.Time
	NotAfter  time.Time
}

// GenerateSelfSigned builds and signs a self-signed certificate for the given
// RSA key and template using the named digest, returning the parsed result.
func GenerateSelfSigned(key *RSAKey, tmpl CertTemplate, algorithm string) (*Certificate, error) {
	if key.Private == nil {
		return nil, x509Error("private key needed to sign certificate")
	}
	sigAlg, err := rsaSigAlg(algorithm)
	if err != nil {
		return nil, err
	}
	serial := tmpl.Serial
	if serial == nil {
		serial = big.NewInt(1)
	}
	subject := pkix.Name{}
	if tmpl.Subject != nil {
		subject = tmpl.Subject.toPKIX()
	}
	issuer := subject
	if tmpl.Issuer != nil {
		issuer = tmpl.Issuer.toPKIX()
	}
	t := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            subject,
		Issuer:             issuer,
		NotBefore:          tmpl.NotBefore,
		NotAfter:           tmpl.NotAfter,
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, t, t, key.Public, key.Private)
	if err != nil {
		return nil, x509Error(err.Error())
	}
	// Re-parsing the DER we just produced cannot fail; the error is elided.
	c, _ := x509.ParseCertificate(der)
	return &Certificate{cert: c}, nil
}

// rsaSigAlg maps a digest name to an RSA x509.SignatureAlgorithm.
func rsaSigAlg(algorithm string) (x509.SignatureAlgorithm, error) {
	switch canonDigestName(algorithm) {
	case "SHA256":
		return x509.SHA256WithRSA, nil
	case "SHA384":
		return x509.SHA384WithRSA, nil
	case "SHA512":
		return x509.SHA512WithRSA, nil
	default:
		return 0, x509Error("unsupported certificate signature digest (" + algorithm + ")")
	}
}
