// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"math/big"
	"testing"
)

func TestBNBasics(t *testing.T) {
	// MRI: OpenSSL::BN.new(255).to_s => "255", to_s(16) => "FF"
	b := NewBN(255)
	if b.String() != "255" {
		t.Errorf("to_s = %s", b.String())
	}
	hexStr, err := b.ToS(16)
	if err != nil {
		t.Fatal(err)
	}
	if hexStr != "FF" {
		t.Errorf("to_s(16) = %s", hexStr)
	}
	dec, err := b.ToS(10)
	if err != nil || dec != "255" {
		t.Errorf("to_s(10) = %s", dec)
	}
}

func TestBNArithmetic(t *testing.T) {
	// MRI: (BN(100) + BN(23)).to_s => "123"
	if NewBN(100).Add(NewBN(23)).String() != "123" {
		t.Error("add")
	}
	if NewBN(100).Sub(NewBN(23)).String() != "77" {
		t.Error("sub")
	}
	if NewBN(6).Mul(NewBN(7)).String() != "42" {
		t.Error("mul")
	}
	m, err := NewBN(17).Mod(NewBN(5))
	if err != nil || m.String() != "2" {
		t.Errorf("mod = %v %v", m, err)
	}
	if _, err := NewBN(17).Mod(NewBN(0)); err == nil {
		t.Error("expected div-by-zero error")
	}
}

func TestBNCompareAndSizes(t *testing.T) {
	if NewBN(5).Cmp(NewBN(7)) != -1 {
		t.Error("cmp")
	}
	b := NewBN(256)
	if b.NumBits() != 9 {
		t.Errorf("num_bits = %d", b.NumBits())
	}
	if b.NumBytes() != 2 {
		t.Errorf("num_bytes = %d", b.NumBytes())
	}
	if len(b.Bytes()) != 2 {
		t.Errorf("bytes len = %d", len(b.Bytes()))
	}
}

func TestBNParse(t *testing.T) {
	d, err := ParseBN("255", 10)
	if err != nil || d.String() != "255" {
		t.Errorf("parse dec = %v %v", d, err)
	}
	h, err := ParseBN("FF", 16)
	if err != nil || h.String() != "255" {
		t.Errorf("parse hex = %v %v", h, err)
	}
	if _, err := ParseBN("zz", 16); err == nil {
		t.Error("expected parse error")
	}
	if _, err := ParseBN("1", 8); err == nil {
		t.Error("expected base error")
	}
}

func TestBNFromBigAndToSError(t *testing.T) {
	b := NewBNFromBig(big.NewInt(99))
	if b.String() != "99" {
		t.Error("from big")
	}
	if got := b.Big(); got.Int64() != 99 {
		t.Error("big getter")
	}
	if _, err := b.ToS(8); err == nil {
		t.Error("expected base error")
	}
}
