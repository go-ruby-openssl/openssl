// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// fromHex decodes a hex literal, failing the test on a bad string.
func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCipherAES256CBCVector(t *testing.T) {
	// MRI: key="k"*32, iv="i"*16, plaintext "hello world this is a test message!!"
	const wantCT = "a180591047cb888d513ae48b2660c14d6104da905e2b455f020571a865c7180be7c69fdbcad9197fd6060b9815125bcd"
	c, err := NewCipher("aes-256-cbc")
	if err != nil {
		t.Fatal(err)
	}
	c.Encrypt()
	if err := c.SetKey(bytes.Repeat([]byte("k"), 32)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetIV(bytes.Repeat([]byte("i"), 16)); err != nil {
		t.Fatal(err)
	}
	out, err := c.Update([]byte("hello world this is a test message!!"))
	if err != nil {
		t.Fatal(err)
	}
	fin, err := c.Final()
	if err != nil {
		t.Fatal(err)
	}
	ct := append(out, fin...)
	if hex.EncodeToString(ct) != wantCT {
		t.Errorf("ct = %s", hex.EncodeToString(ct))
	}
	// Round-trip decrypt.
	d, _ := NewCipher("aes-256-cbc")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 16))
	p1, err := d.Update(ct)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := d.Final()
	if err != nil {
		t.Fatal(err)
	}
	if string(append(p1, p2...)) != "hello world this is a test message!!" {
		t.Errorf("roundtrip = %q", string(append(p1, p2...)))
	}
}

func TestCipherCBCStreamingChunks(t *testing.T) {
	pt := []byte("the quick brown fox jumps over the lazy dog!!")
	c, _ := NewCipher("aes-128-cbc")
	c.Encrypt()
	c.SetKey(bytes.Repeat([]byte("k"), 16))
	c.SetIV(bytes.Repeat([]byte("i"), 16))
	var ct []byte
	for _, chunk := range [][]byte{pt[:5], pt[5:20], pt[20:]} {
		out, err := c.Update(chunk)
		if err != nil {
			t.Fatal(err)
		}
		ct = append(ct, out...)
	}
	fin, _ := c.Final()
	ct = append(ct, fin...)

	d, _ := NewCipher("aes-128-cbc")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 16))
	d.SetIV(bytes.Repeat([]byte("i"), 16))
	var rt []byte
	for _, chunk := range [][]byte{ct[:7], ct[7:33], ct[33:]} {
		out, err := d.Update(chunk)
		if err != nil {
			t.Fatal(err)
		}
		rt = append(rt, out...)
	}
	fin2, err := d.Final()
	if err != nil {
		t.Fatal(err)
	}
	rt = append(rt, fin2...)
	if !bytes.Equal(rt, pt) {
		t.Errorf("streamed roundtrip = %q", rt)
	}
}

func TestCipherAES256GCMVector(t *testing.T) {
	// MRI: key="k"*32, iv="i"*12, aad "header", plaintext "secret payload"
	const wantCT = "a9e19b06578c81749a2d8d17fa73"
	const wantTag = "873d5e19a0c95c05577f97df696290a5"
	c, _ := NewCipher("aes-256-gcm")
	c.Encrypt()
	c.SetKey(bytes.Repeat([]byte("k"), 32))
	c.SetIV(bytes.Repeat([]byte("i"), 12))
	if err := c.SetAuthData([]byte("header")); err != nil {
		t.Fatal(err)
	}
	out, _ := c.Update([]byte("secret payload"))
	fin, err := c.Final()
	if err != nil {
		t.Fatal(err)
	}
	ct := append(out, fin...)
	if hex.EncodeToString(ct) != wantCT {
		t.Errorf("gcm ct = %s", hex.EncodeToString(ct))
	}
	tag, err := c.AuthTag()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tag) != wantTag {
		t.Errorf("gcm tag = %s", hex.EncodeToString(tag))
	}

	// Decrypt with the captured tag.
	d, _ := NewCipher("aes-256-gcm")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 12))
	d.SetAuthData([]byte("header"))
	d.SetAuthTag(tag)
	d.Update(ct)
	pt, err := d.Final()
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "secret payload" {
		t.Errorf("gcm pt = %q", pt)
	}
}

func TestCipherGCMTamperFails(t *testing.T) {
	c, _ := NewCipher("aes-256-gcm")
	c.Encrypt()
	c.SetKey(bytes.Repeat([]byte("k"), 32))
	c.SetIV(bytes.Repeat([]byte("i"), 12))
	c.Update([]byte("secret payload"))
	ct, _ := c.Final()
	tag, _ := c.AuthTag()
	tag[0] ^= 0xff // tamper

	d, _ := NewCipher("aes-256-gcm")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 12))
	d.SetAuthTag(tag)
	d.Update(ct)
	if _, err := d.Final(); err == nil {
		t.Error("expected auth failure on tampered tag")
	}
}

func TestCipherGCMDecryptWithoutTag(t *testing.T) {
	d, _ := NewCipher("aes-256-gcm")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 12))
	d.Update([]byte("x"))
	if _, err := d.Final(); err == nil {
		t.Error("expected error without auth tag")
	}
}

func TestCipherAES128CTRVector(t *testing.T) {
	// MRI: key="k"*16, iv="i"*16, plaintext "counter mode!"
	const wantCT = "3fde8f91973e3198e74eacb489"
	c, _ := NewCipher("aes-128-ctr")
	c.Encrypt()
	c.SetKey(bytes.Repeat([]byte("k"), 16))
	c.SetIV(bytes.Repeat([]byte("i"), 16))
	out, _ := c.Update([]byte("counter mode!"))
	fin, err := c.Final()
	if err != nil {
		t.Fatal(err)
	}
	ct := append(out, fin...)
	if hex.EncodeToString(ct) != wantCT {
		t.Errorf("ctr ct = %s", hex.EncodeToString(ct))
	}
	// CTR decrypt is the same keystream.
	d, _ := NewCipher("aes-128-ctr")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 16))
	d.SetIV(bytes.Repeat([]byte("i"), 16))
	p, _ := d.Update(ct)
	pf, _ := d.Final()
	if string(append(p, pf...)) != "counter mode!" {
		t.Errorf("ctr roundtrip failed")
	}
}

func TestCipherMetadata(t *testing.T) {
	c, _ := NewCipher("aes-192-cbc")
	if c.Name() != "aes-192-cbc" || c.KeyLen() != 24 || c.IVLen() != 16 {
		t.Errorf("cbc metadata wrong: %s %d %d", c.Name(), c.KeyLen(), c.IVLen())
	}
	g, _ := NewCipher("aes-256-gcm")
	if g.IVLen() != 12 {
		t.Errorf("gcm iv len = %d", g.IVLen())
	}
}

func TestCipherNameErrors(t *testing.T) {
	for _, bad := range []string{"des-cbc", "aes-200-cbc", "aes-256-xyz", "aes-cbc", "aes-abc-cbc"} {
		if _, err := NewCipher(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestCipherKeyIVLengthErrors(t *testing.T) {
	c, _ := NewCipher("aes-256-cbc")
	c.Encrypt()
	if err := c.SetKey([]byte("short")); err == nil {
		t.Error("expected key length error")
	}
	if err := c.SetIV([]byte("short")); err == nil {
		t.Error("expected iv length error")
	}
}

func TestCipherUpdateBeforeReady(t *testing.T) {
	c, _ := NewCipher("aes-256-cbc")
	if _, err := c.Update([]byte("x")); err == nil {
		t.Error("expected error: no direction")
	}
	c.Encrypt()
	if _, err := c.Update([]byte("x")); err == nil {
		t.Error("expected error: no key")
	}
	c.SetKey(bytes.Repeat([]byte("k"), 32))
	if _, err := c.Update([]byte("x")); err == nil {
		t.Error("expected error: no iv")
	}
	// Final has the same guard.
	c2, _ := NewCipher("aes-256-cbc")
	if _, err := c2.Final(); err == nil {
		t.Error("expected error from Final before ready")
	}
}

func TestCipherAuthDataOnNonAEAD(t *testing.T) {
	c, _ := NewCipher("aes-256-cbc")
	if err := c.SetAuthData([]byte("x")); err == nil {
		t.Error("expected AEAD error")
	}
	if err := c.SetAuthTag([]byte("x")); err == nil {
		t.Error("expected AEAD error")
	}
	if _, err := c.AuthTag(); err == nil {
		t.Error("expected AEAD error")
	}
}

func TestCipherAuthTagBeforeFinal(t *testing.T) {
	c, _ := NewCipher("aes-256-gcm")
	c.Encrypt()
	c.SetKey(bytes.Repeat([]byte("k"), 32))
	c.SetIV(bytes.Repeat([]byte("i"), 12))
	if _, err := c.AuthTag(); err == nil {
		t.Error("expected error before Final")
	}
}

func TestCBCBadDecrypt(t *testing.T) {
	// Decrypt random data: padding check should fail in Final.
	d, _ := NewCipher("aes-256-cbc")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 16))
	d.Update(fromHex(t, "00112233445566778899aabbccddeeff"))
	if _, err := d.Final(); err == nil {
		t.Error("expected bad-decrypt error")
	}
}

func TestCBCEmptyFinalErrors(t *testing.T) {
	d, _ := NewCipher("aes-256-cbc")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 16))
	// No input at all: empty final block.
	if _, err := d.Final(); err == nil {
		t.Error("expected error on empty final")
	}
}

func TestCBCPartialBlockFinalErrors(t *testing.T) {
	d, _ := NewCipher("aes-256-cbc")
	d.Decrypt()
	d.SetKey(bytes.Repeat([]byte("k"), 32))
	d.SetIV(bytes.Repeat([]byte("i"), 16))
	d.Update([]byte("not16")) // 5 bytes, never forms a block
	if _, err := d.Final(); err == nil {
		t.Error("expected wrong-final-block-length error")
	}
}

func TestPKCS7Unpad(t *testing.T) {
	// Direct unit coverage of the malformed-padding branches.
	if _, err := pkcs7Unpad(nil, 16); err == nil {
		t.Error("expected error on empty")
	}
	if _, err := pkcs7Unpad(make([]byte, 16), 16); err == nil {
		t.Error("expected error: pad byte 0")
	}
	block := make([]byte, 16)
	block[15] = 0x20 // pad value > blockSize
	if _, err := pkcs7Unpad(block, 16); err == nil {
		t.Error("expected error: pad too large")
	}
	bad := make([]byte, 16)
	bad[15] = 0x03
	bad[14] = 0x03
	bad[13] = 0x02 // inconsistent
	if _, err := pkcs7Unpad(bad, 16); err == nil {
		t.Error("expected error: inconsistent pad")
	}
}
