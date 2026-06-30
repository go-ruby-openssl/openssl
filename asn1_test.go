// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// derHex encodes an ASN1Value and returns its hex, failing on error.
func derHex(t *testing.T, v *ASN1Value) string {
	t.Helper()
	der, err := v.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(der)
}

func TestASN1EncodeVectors(t *testing.T) {
	// MRI oracle vectors.
	cases := []struct {
		name string
		v    *ASN1Value
		want string
	}{
		{"int255", Int(255), "020200ff"},
		{"octet", OctetString([]byte("hi")), "04026869"},
		{"bool", Bool(true), "0101ff"},
		{"null", Null(), "0500"},
		{"oid", ObjectID("1.2.840.113549.1.1.1"), "06092a864886f70d010101"},
		{"seq", Sequence(Int(1), Int(2)), "3006020101020102"},
	}
	for _, c := range cases {
		if got := derHex(t, c.v); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestASN1IntegerEncoding(t *testing.T) {
	cases := map[int64]string{
		0:    "020100",
		127:  "02017f",
		128:  "02020080",
		255:  "020200ff",
		-1:   "0201ff",
		-128: "020180",
		-129: "0202ff7f",
		256:  "02020100",
	}
	for n, want := range cases {
		if got := derHex(t, Int(n)); got != want {
			t.Errorf("Int(%d): got %s want %s", n, got, want)
		}
	}
	// Big.Int path.
	big200 := IntBig(big.NewInt(200))
	if got := derHex(t, big200); got != "020200c8" {
		t.Errorf("IntBig(200) = %s", got)
	}
}

func TestASN1MoreTypes(t *testing.T) {
	if got := derHex(t, UTF8String("hi")); got != "0c026869" {
		t.Errorf("utf8 = %s", got)
	}
	if got := derHex(t, Set(Int(1))); got != "3103020101" {
		t.Errorf("set = %s", got)
	}
	bs := &ASN1Value{Tag: tagBitString, Value: []byte{0xab}}
	if got := derHex(t, bs); got != "030200ab" {
		t.Errorf("bitstring = %s", got)
	}
}

func TestASN1LongLength(t *testing.T) {
	// A 200-byte octet string forces multi-byte length encoding (0x81 0xc8).
	der, err := OctetString(make([]byte, 200)).ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if der[0] != 0x04 || der[1] != 0x81 || der[2] != 0xc8 {
		t.Errorf("long length header = % x", der[:3])
	}
	// And a 300-byte one forces two length octets.
	der2, _ := OctetString(make([]byte, 300)).ToDER()
	if der2[1] != 0x82 || der2[2] != 0x01 || der2[3] != 0x2c {
		t.Errorf("two-octet length header = % x", der2[:4])
	}
}

func TestASN1DecodeRoundTrip(t *testing.T) {
	der, _ := Int(255).ToDER()
	v, err := DecodeASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if v.Tag != tagInteger {
		t.Errorf("tag = %d", v.Tag)
	}
	if v.Value.(*big.Int).Int64() != 255 {
		t.Errorf("value = %v", v.Value)
	}
}

func TestASN1DecodeAllTypes(t *testing.T) {
	// Boolean
	b, _ := DecodeASN1(fromHex(t, "0101ff"))
	if b.Value.(bool) != true {
		t.Error("bool decode")
	}
	bf, _ := DecodeASN1(fromHex(t, "010100"))
	if bf.Value.(bool) != false {
		t.Error("bool false decode")
	}
	// Null
	if n, _ := DecodeASN1(fromHex(t, "0500")); n.Tag != tagNull {
		t.Error("null decode")
	}
	// OctetString
	o, _ := DecodeASN1(fromHex(t, "04026869"))
	if string(o.Value.([]byte)) != "hi" {
		t.Error("octet decode")
	}
	// OID
	oid, _ := DecodeASN1(fromHex(t, "06092a864886f70d010101"))
	if oid.Value.(string) != "1.2.840.113549.1.1.1" {
		t.Errorf("oid decode = %v", oid.Value)
	}
	// UTF8String
	u, _ := DecodeASN1(fromHex(t, "0c026869"))
	if u.Value.(string) != "hi" {
		t.Error("utf8 decode")
	}
	// BitString
	bs, _ := DecodeASN1(fromHex(t, "030200ab"))
	if hex.EncodeToString(bs.Value.([]byte)) != "ab" {
		t.Error("bitstring decode")
	}
	// Sequence
	seq, _ := DecodeASN1(fromHex(t, "3006020101020102"))
	kids := seq.Value.([]*ASN1Value)
	if len(kids) != 2 || kids[1].Value.(*big.Int).Int64() != 2 {
		t.Error("sequence decode")
	}
	// Negative integer round-trip
	neg, _ := DecodeASN1(fromHex(t, "0201ff"))
	if neg.Value.(*big.Int).Int64() != -1 {
		t.Errorf("neg decode = %v", neg.Value)
	}
	// Zero-length integer decodes to 0.
	z, _ := DecodeASN1(fromHex(t, "0200"))
	if z.Value.(*big.Int).Sign() != 0 {
		t.Error("zero int decode")
	}
}

func TestASN1DecodeErrors(t *testing.T) {
	bad := [][]byte{
		{0x04},                   // too short
		{0x1f, 0x01},             // multi-byte tag
		fromHex(t, "020200ff00"), // trailing data
		fromHex(t, "0405ffff"),   // length exceeds buffer
		{0x01, 0x00},             // boolean wrong length (0)
		fromHex(t, "050100"),     // null wrong length
		{0x03, 0x00},             // empty bit string
		fromHex(t, "0600"),       // empty OID
	}
	for i, b := range bad {
		if _, err := DecodeASN1(b); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestASN1DecodeLengthVariants(t *testing.T) {
	// Long-form length round-trips.
	der, _ := OctetString(make([]byte, 200)).ToDER()
	v, err := DecodeASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Value.([]byte)) != 200 {
		t.Errorf("decoded len = %d", len(v.Value.([]byte)))
	}
	// Invalid length: indefinite (0x80) and over-long.
	if _, _, err := decodeLength([]byte{0x80}); err == nil {
		t.Error("expected error on 0x80 length")
	}
	if _, _, err := decodeLength([]byte{0x85, 1, 2, 3, 4, 5}); err == nil {
		t.Error("expected error on 5-byte length")
	}
	if _, _, err := decodeLength(nil); err == nil {
		t.Error("expected error on empty length")
	}
}

func TestASN1EncodeErrors(t *testing.T) {
	cases := []*ASN1Value{
		{Tag: tagBoolean, Value: 5},
		{Tag: tagInteger, Value: "x"},
		{Tag: tagOctetString, Value: 5},
		{Tag: tagBitString, Value: 5},
		{Tag: tagUTF8String, Value: 5},
		{Tag: tagObjectID, Value: 5},
		{Tag: tagSequence, Value: 5},
		{Tag: 99, Value: nil},
		{Tag: tagObjectID, Value: "1"},                     // too few arcs
		{Tag: tagObjectID, Value: "3.1.1"},                 // first arc > 2
		{Tag: tagObjectID, Value: "1.40.1"},                // second arc >= 40 for first<2
		{Tag: tagObjectID, Value: "1.2.x"},                 // non-numeric arc
		{Tag: tagObjectID, Value: "1..2"},                  // empty arc
		{Tag: tagSequence, Value: []*ASN1Value{{Tag: 99}}}, // child encode fails
	}
	for i, c := range cases {
		if _, err := c.ToDER(); err == nil {
			t.Errorf("case %d: expected encode error", i)
		}
	}
}

func TestASN1OIDArc0(t *testing.T) {
	// OID with a zero arc (0.0) and arc value 0 in base128.
	der, err := ObjectID("0.0").ToDER()
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecodeASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if v.Value.(string) != "0.0" {
		t.Errorf("oid 0.0 round-trip = %v", v.Value)
	}
}

func TestASN1DecodeTruncatedOID(t *testing.T) {
	// Final OID byte (after the first arc) has the continuation bit set with
	// no following byte: truncated.
	if _, err := DecodeASN1(fromHex(t, "06022a80")); err == nil {
		t.Error("expected truncated-OID error")
	}
}

func TestASN1UnsupportedDecodeTag(t *testing.T) {
	// Tag 0x09 (REAL) is not implemented.
	if _, err := DecodeASN1(fromHex(t, "0900")); err == nil {
		t.Error("expected unsupported-tag error")
	}
}

func TestASN1DecodeNestedErrors(t *testing.T) {
	// SEQUENCE (30 02) whose child is an OID with a multi-byte length prefix
	// (0x81) but no following length byte: the nested decodeLength error must
	// propagate up through decodeOne.
	if _, err := DecodeASN1(fromHex(t, "30020681")); err == nil {
		t.Error("expected nested length error")
	}
	// SEQUENCE whose child claims a length beyond the buffer.
	if _, err := DecodeASN1(fromHex(t, "300306810a")); err == nil {
		t.Error("expected nested length-exceeds-buffer error")
	}
	// SEQUENCE whose child is an unsupported tag (09 = REAL).
	if _, err := DecodeASN1(fromHex(t, "30020900")); err == nil {
		t.Error("expected nested unsupported-tag error")
	}
}

func TestASN1OIDArcGE80(t *testing.T) {
	// 2.100.3 encodes its first subidentifier as 180 (0x81 0x34), exercising the
	// first-byte >= 80 decode branch.
	v, err := DecodeASN1(fromHex(t, "0603813403"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Value.(string) != "2.100.3" {
		t.Errorf("oid = %v", v.Value)
	}
}

func TestASN1Enumerated(t *testing.T) {
	v := &ASN1Value{Tag: tagEnumerated, Value: big.NewInt(5)}
	der, err := v.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(der) != "0a0105" {
		t.Errorf("enumerated = %s", hex.EncodeToString(der))
	}
	d, _ := DecodeASN1(der)
	if d.Value.(*big.Int).Int64() != 5 {
		t.Error("enumerated decode")
	}
}
