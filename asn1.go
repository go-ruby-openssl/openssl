// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"math/big"
)

// ASN.1 universal tag numbers this package handles, matching MRI's
// OpenSSL::ASN1 tag constants.
const (
	tagBoolean      = 0x01
	tagInteger      = 0x02
	tagBitString    = 0x03
	tagOctetString  = 0x04
	tagNull         = 0x05
	tagObjectID     = 0x06
	tagEnumerated   = 0x0a
	tagUTF8String   = 0x0c
	tagSequence     = 0x10
	tagSet          = 0x11
	tagPrintableStr = 0x13
	tagIA5String    = 0x16
)

// ASN1Value is a decoded ASN.1 element. Tag is the universal tag number; Value
// holds the typed Go value (bool, *big.Int, []byte, string, []*ASN1Value for
// constructed types); Constructed marks SEQUENCE/SET.
type ASN1Value struct {
	Tag         int
	Constructed bool
	Value       any
}

// asn1Integer encodes a big.Int the way DER (and MRI) do: the minimal
// two's-complement big-endian content, with a leading 0x00 added when the high
// bit would otherwise make a positive number look negative. This reproduces
// MRI's 0x02 0x02 0x00 0xff for the value 255.
func asn1Integer(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0x00}
	}
	if n.Sign() > 0 {
		b := n.Bytes()
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return b
	}
	// Negative: pick the minimal byte width whose signed range still holds n
	// (so -128 fits in one byte as 0x80, but -129 needs two as 0xff 0x7f),
	// then emit the two's-complement over that width.
	length := 1
	for {
		min := new(big.Int).Lsh(big.NewInt(1), uint(length*8-1)) // 2^(8*len-1)
		min.Neg(min)                                             // -2^(8*len-1)
		if n.Cmp(min) >= 0 {
			break
		}
		length++
	}
	mod := new(big.Int).Lsh(big.NewInt(1), uint(length*8))
	tc := new(big.Int).Add(mod, n)
	b := tc.Bytes()
	out := make([]byte, length)
	copy(out[length-len(b):], b) // left-pad with the implicit 0x00 from Bytes()
	return out
}

// encodeLength returns the DER length octets for n.
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var rev []byte
	for n > 0 {
		rev = append(rev, byte(n&0xff))
		n >>= 8
	}
	out := make([]byte, 0, len(rev)+1)
	out = append(out, byte(0x80|len(rev)))
	for i := len(rev) - 1; i >= 0; i-- {
		out = append(out, rev[i])
	}
	return out
}

// encodeOID encodes a dotted object identifier ("1.2.840.113549.1.1.1") into
// DER content octets.
func encodeOID(oid string) ([]byte, error) {
	arcs, err := parseOIDArcs(oid)
	if err != nil {
		return nil, err
	}
	if len(arcs) < 2 {
		return nil, asn1Error("OID must have at least two arcs")
	}
	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
		return nil, asn1Error("invalid OID arcs")
	}
	out := encodeBase128(arcs[0]*40 + arcs[1])
	for _, a := range arcs[2:] {
		out = append(out, encodeBase128(a)...)
	}
	return out, nil
}

// parseOIDArcs splits a dotted OID into its integer arcs.
func parseOIDArcs(oid string) ([]int, error) {
	var arcs []int
	cur := 0
	has := false
	for i := 0; i <= len(oid); i++ {
		if i == len(oid) || oid[i] == '.' {
			if !has {
				return nil, asn1Error("malformed OID")
			}
			arcs = append(arcs, cur)
			cur, has = 0, false
			continue
		}
		ch := oid[i]
		if ch < '0' || ch > '9' {
			return nil, asn1Error("malformed OID")
		}
		cur = cur*10 + int(ch-'0')
		has = true
	}
	return arcs, nil
}

// encodeBase128 encodes a non-negative integer in DER's base-128 OID form.
func encodeBase128(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var rev []byte
	for n > 0 {
		rev = append(rev, byte(n&0x7f))
		n >>= 7
	}
	out := make([]byte, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		b := rev[i]
		if i != 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

// emit assembles a TLV from a tag byte and content.
func emit(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = append(out, encodeLength(len(content))...)
	out = append(out, content...)
	return out
}

// ToDER encodes the ASN1Value to DER, mirroring OpenSSL::ASN1::*#to_der.
func (a *ASN1Value) ToDER() ([]byte, error) {
	switch a.Tag {
	case tagBoolean:
		b, ok := a.Value.(bool)
		if !ok {
			return nil, asn1Error("Boolean value must be a bool")
		}
		v := byte(0x00)
		if b {
			v = 0xff
		}
		return emit(tagBoolean, []byte{v}), nil
	case tagInteger, tagEnumerated:
		n, ok := a.Value.(*big.Int)
		if !ok {
			return nil, asn1Error("Integer value must be a *big.Int")
		}
		return emit(byte(a.Tag), asn1Integer(n)), nil
	case tagNull:
		return emit(tagNull, nil), nil
	case tagOctetString:
		b, ok := a.Value.([]byte)
		if !ok {
			return nil, asn1Error("OctetString value must be []byte")
		}
		return emit(tagOctetString, b), nil
	case tagBitString:
		b, ok := a.Value.([]byte)
		if !ok {
			return nil, asn1Error("BitString value must be []byte")
		}
		// Prefix the "unused bits" octet (always 0 for byte-aligned data).
		return emit(tagBitString, append([]byte{0x00}, b...)), nil
	case tagUTF8String, tagPrintableStr, tagIA5String:
		s, ok := a.Value.(string)
		if !ok {
			return nil, asn1Error("String value must be a string")
		}
		return emit(byte(a.Tag), []byte(s)), nil
	case tagObjectID:
		s, ok := a.Value.(string)
		if !ok {
			return nil, asn1Error("ObjectId value must be a dotted string")
		}
		content, err := encodeOID(s)
		if err != nil {
			return nil, err
		}
		return emit(tagObjectID, content), nil
	case tagSequence, tagSet:
		children, ok := a.Value.([]*ASN1Value)
		if !ok {
			return nil, asn1Error("constructed value must be []*ASN1Value")
		}
		var content []byte
		for _, ch := range children {
			der, err := ch.ToDER()
			if err != nil {
				return nil, err
			}
			content = append(content, der...)
		}
		return emit(byte(0x20|a.Tag), content), nil
	default:
		return nil, asn1Error("unsupported ASN.1 tag")
	}
}

// Constructors mirroring OpenSSL::ASN1::* .new helpers.

// Bool builds an ASN.1 BOOLEAN.
func Bool(v bool) *ASN1Value { return &ASN1Value{Tag: tagBoolean, Value: v} }

// Int builds an ASN.1 INTEGER from an int64.
func Int(v int64) *ASN1Value { return &ASN1Value{Tag: tagInteger, Value: big.NewInt(v)} }

// IntBig builds an ASN.1 INTEGER from a *big.Int.
func IntBig(v *big.Int) *ASN1Value {
	return &ASN1Value{Tag: tagInteger, Value: new(big.Int).Set(v)}
}

// Null builds an ASN.1 NULL.
func Null() *ASN1Value { return &ASN1Value{Tag: tagNull} }

// OctetString builds an ASN.1 OCTET STRING.
func OctetString(b []byte) *ASN1Value {
	return &ASN1Value{Tag: tagOctetString, Value: append([]byte(nil), b...)}
}

// UTF8String builds an ASN.1 UTF8String.
func UTF8String(s string) *ASN1Value { return &ASN1Value{Tag: tagUTF8String, Value: s} }

// ObjectID builds an ASN.1 OBJECT IDENTIFIER from a dotted string.
func ObjectID(oid string) *ASN1Value { return &ASN1Value{Tag: tagObjectID, Value: oid} }

// Sequence builds an ASN.1 SEQUENCE of children.
func Sequence(children ...*ASN1Value) *ASN1Value {
	return &ASN1Value{Tag: tagSequence, Constructed: true, Value: children}
}

// Set builds an ASN.1 SET of children.
func Set(children ...*ASN1Value) *ASN1Value {
	return &ASN1Value{Tag: tagSet, Constructed: true, Value: children}
}

// DecodeASN1 parses a single DER-encoded ASN.1 element, mirroring
// OpenSSL::ASN1.decode. It returns the value and the number of bytes consumed.
func DecodeASN1(der []byte) (*ASN1Value, error) {
	v, n, err := decodeOne(der)
	if err != nil {
		return nil, err
	}
	if n != len(der) {
		return nil, asn1Error("trailing data after ASN.1 element")
	}
	return v, nil
}

// decodeOne parses one TLV from the head of b.
func decodeOne(b []byte) (*ASN1Value, int, error) {
	if len(b) < 2 {
		return nil, 0, asn1Error("ASN.1 element too short")
	}
	id := b[0]
	if id&0x1f == 0x1f {
		return nil, 0, asn1Error("multi-byte tags unsupported")
	}
	constructed := id&0x20 != 0
	tag := int(id & 0x1f)
	length, hdr, err := decodeLength(b[1:])
	if err != nil {
		return nil, 0, err
	}
	start := 1 + hdr
	end := start + length
	if end > len(b) || end < start {
		return nil, 0, asn1Error("ASN.1 length exceeds buffer")
	}
	content := b[start:end]
	val, err := decodeContent(tag, constructed, content)
	if err != nil {
		return nil, 0, err
	}
	return val, end, nil
}

// decodeLength reads DER length octets, returning the length and header size.
func decodeLength(b []byte) (length, hdr int, err error) {
	if len(b) == 0 {
		return 0, 0, asn1Error("missing length")
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	num := int(b[0] & 0x7f)
	if num == 0 || num > 4 || len(b) < 1+num {
		return 0, 0, asn1Error("invalid length encoding")
	}
	v := 0
	for i := 1; i <= num; i++ {
		v = v<<8 | int(b[i])
	}
	return v, 1 + num, nil
}

// decodeContent builds an ASN1Value from a tag and its raw content.
func decodeContent(tag int, constructed bool, content []byte) (*ASN1Value, error) {
	if constructed {
		var children []*ASN1Value
		off := 0
		for off < len(content) {
			child, n, err := decodeOne(content[off:])
			if err != nil {
				return nil, err
			}
			children = append(children, child)
			off += n
		}
		return &ASN1Value{Tag: tag, Constructed: true, Value: children}, nil
	}
	switch tag {
	case tagBoolean:
		if len(content) != 1 {
			return nil, asn1Error("malformed BOOLEAN")
		}
		return &ASN1Value{Tag: tag, Value: content[0] != 0x00}, nil
	case tagInteger, tagEnumerated:
		return &ASN1Value{Tag: tag, Value: decodeInteger(content)}, nil
	case tagNull:
		if len(content) != 0 {
			return nil, asn1Error("malformed NULL")
		}
		return &ASN1Value{Tag: tag}, nil
	case tagOctetString:
		return &ASN1Value{Tag: tag, Value: append([]byte(nil), content...)}, nil
	case tagBitString:
		if len(content) == 0 {
			return nil, asn1Error("malformed BIT STRING")
		}
		return &ASN1Value{Tag: tag, Value: append([]byte(nil), content[1:]...)}, nil
	case tagObjectID:
		oid, err := decodeOID(content)
		if err != nil {
			return nil, err
		}
		return &ASN1Value{Tag: tag, Value: oid}, nil
	case tagUTF8String, tagPrintableStr, tagIA5String:
		return &ASN1Value{Tag: tag, Value: string(content)}, nil
	default:
		return nil, asn1Error("unsupported ASN.1 tag in decode")
	}
}

// decodeInteger decodes two's-complement INTEGER content into a *big.Int.
func decodeInteger(content []byte) *big.Int {
	if len(content) == 0 {
		return big.NewInt(0)
	}
	n := new(big.Int).SetBytes(content)
	if content[0]&0x80 != 0 { // negative
		mod := new(big.Int).Lsh(big.NewInt(1), uint(len(content)*8))
		n.Sub(n, mod)
	}
	return n
}

// decodeOID decodes OID content octets into a dotted string.
func decodeOID(content []byte) (string, error) {
	if len(content) == 0 {
		return "", asn1Error("empty OID")
	}
	// Decode the base-128 subidentifiers; the first encodes both leading arcs
	// as 40*arc0 + arc1 (which can itself span multiple bytes, e.g. 2.100).
	subids := make([]int, 0, len(content))
	val := 0
	pending := false
	for _, b := range content {
		val = val<<7 | int(b&0x7f)
		pending = true
		if b&0x80 == 0 {
			subids = append(subids, val)
			val, pending = 0, false
		}
	}
	if pending {
		return "", asn1Error("truncated OID")
	}
	arcs := make([]int, 0, len(subids)+1)
	if subids[0] < 80 {
		arcs = append(arcs, subids[0]/40, subids[0]%40)
	} else {
		arcs = append(arcs, 2, subids[0]-80)
	}
	arcs = append(arcs, subids[1:]...)
	out := make([]byte, 0, len(arcs)*2)
	for i, a := range arcs {
		if i > 0 {
			out = append(out, '.')
		}
		out = appendInt(out, a)
	}
	return string(out), nil
}

// appendInt appends the decimal text of a non-negative int to dst.
func appendInt(dst []byte, n int) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(dst, tmp[i:]...)
}
