// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"math/big"
	"strings"
)

// BN is an arbitrary-precision integer, mirroring OpenSSL::BN over math/big.
type BN struct {
	v *big.Int
}

// NewBN builds a BN from an int64.
func NewBN(n int64) *BN { return &BN{v: big.NewInt(n)} }

// NewBNFromBig builds a BN from an existing *big.Int (copied).
func NewBNFromBig(n *big.Int) *BN { return &BN{v: new(big.Int).Set(n)} }

// ParseBN parses a BN from its decimal (base 10) or hex (base 16) string form,
// mirroring OpenSSL::BN.new(str, base). base must be 10 or 16.
func ParseBN(s string, base int) (*BN, error) {
	if base != 10 && base != 16 {
		return nil, bnError("unsupported base")
	}
	v, ok := new(big.Int).SetString(strings.TrimSpace(s), base)
	if !ok {
		return nil, bnError("invalid bignum")
	}
	return &BN{v: v}, nil
}

// Big returns a copy of the underlying *big.Int.
func (b *BN) Big() *big.Int { return new(big.Int).Set(b.v) }

// String returns the decimal representation (#to_s with no base).
func (b *BN) String() string { return b.v.String() }

// ToS returns the representation in the given base: decimal for 10, upper-case
// hex for 16 (matching MRI's #to_s(16), which emits upper-case hex).
func (b *BN) ToS(base int) (string, error) {
	switch base {
	case 10:
		return b.v.String(), nil
	case 16:
		return strings.ToUpper(b.v.Text(16)), nil
	default:
		return "", bnError("unsupported base")
	}
}

// Add returns b + o.
func (b *BN) Add(o *BN) *BN { return &BN{v: new(big.Int).Add(b.v, o.v)} }

// Sub returns b - o.
func (b *BN) Sub(o *BN) *BN { return &BN{v: new(big.Int).Sub(b.v, o.v)} }

// Mul returns b * o.
func (b *BN) Mul(o *BN) *BN { return &BN{v: new(big.Int).Mul(b.v, o.v)} }

// Mod returns b mod o, erroring on a zero modulus.
func (b *BN) Mod(o *BN) (*BN, error) {
	if o.v.Sign() == 0 {
		return nil, bnError("div by zero")
	}
	return &BN{v: new(big.Int).Mod(b.v, o.v)}, nil
}

// Cmp compares b and o, returning -1, 0 or +1.
func (b *BN) Cmp(o *BN) int { return b.v.Cmp(o.v) }

// NumBits returns the number of significant bits (#num_bits).
func (b *BN) NumBits() int { return b.v.BitLen() }

// NumBytes returns the minimum number of bytes to represent the magnitude
// (#num_bytes).
func (b *BN) NumBytes() int { return (b.v.BitLen() + 7) / 8 }

// Bytes returns the big-endian magnitude bytes (#to_s(2) / OpenSSL's i2s).
func (b *BN) Bytes() []byte { return b.v.Bytes() }
