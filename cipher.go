// Copyright (c) the go-ruby-openssl/openssl authors
//
// SPDX-License-Identifier: BSD-3-Clause

package openssl

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"strings"
)

// cipherMode enumerates the block-cipher modes this package implements.
type cipherMode int

const (
	modeCBC cipherMode = iota
	modeGCM
	modeCTR
)

// cipherSpec is the parsed form of an MRI cipher name like "aes-256-gcm":
// algorithm, key length in bytes, and mode.
type cipherSpec struct {
	keyLen int
	mode   cipherMode
}

// parseCipherName decodes an MRI cipher name ("aes-128-cbc", "aes-256-gcm",
// "aes-128-ctr"; case-insensitive) into a cipherSpec, returning an error for an
// unsupported cipher.
func parseCipherName(name string) (cipherSpec, error) {
	parts := strings.Split(strings.ToLower(name), "-")
	if len(parts) != 3 || parts[0] != "aes" {
		return cipherSpec{}, cipherError("unsupported cipher algorithm (" + name + ")")
	}
	bits, err := strconv.Atoi(parts[1])
	if err != nil || (bits != 128 && bits != 192 && bits != 256) {
		return cipherSpec{}, cipherError("unsupported cipher algorithm (" + name + ")")
	}
	var mode cipherMode
	switch parts[2] {
	case "cbc":
		mode = modeCBC
	case "gcm":
		mode = modeGCM
	case "ctr":
		mode = modeCTR
	default:
		return cipherSpec{}, cipherError("unsupported cipher algorithm (" + name + ")")
	}
	return cipherSpec{keyLen: bits / 8, mode: mode}, nil
}

// Cipher is a symmetric AES cipher, mirroring OpenSSL::Cipher. The lifecycle
// matches MRI: construct with NewCipher, call Encrypt or Decrypt to pick the
// direction, set Key and IV, optionally feed AuthData (GCM), stream plaintext/
// ciphertext through Update, and emit the trailing block with Final.
type Cipher struct {
	spec cipherSpec
	name string

	encrypt bool // true after Encrypt, false after Decrypt
	dirSet  bool // whether a direction has been chosen

	key   []byte
	iv    []byte
	block cipher.Block // AES block, built when the key is set

	// CBC/CTR streaming state, created lazily on the first Update once key+iv
	// are present.
	stream cipher.Stream    // CTR keystream
	cbc    cipher.BlockMode // CBC chain
	buf    []byte           // CBC residual partial block awaiting padding

	// GCM state buffers the whole message (GCM is not a streaming AEAD here)
	// and the AAD, finalising in Final to match MRI's auth_tag semantics.
	aad     []byte
	gcmData []byte
	authTag []byte // set after a successful Final on encrypt; required for decrypt
}

// blockSize is AES's fixed 16-byte block.
const aesBlockSize = aes.BlockSize

// NewCipher constructs a Cipher for an MRI cipher name (e.g. "aes-256-gcm").
func NewCipher(name string) (*Cipher, error) {
	spec, err := parseCipherName(name)
	if err != nil {
		return nil, err
	}
	return &Cipher{spec: spec, name: strings.ToLower(name)}, nil
}

// Name returns the canonical (lower-case) cipher name.
func (c *Cipher) Name() string { return c.name }

// KeyLen returns the required key length in bytes.
func (c *Cipher) KeyLen() int { return c.spec.keyLen }

// IVLen returns the IV/nonce length in bytes: 12 for GCM, 16 otherwise,
// matching MRI's defaults.
func (c *Cipher) IVLen() int {
	if c.spec.mode == modeGCM {
		return 12
	}
	return aesBlockSize
}

// Encrypt selects the encryption direction (OpenSSL::Cipher#encrypt).
func (c *Cipher) Encrypt() *Cipher { c.encrypt, c.dirSet = true, true; return c }

// Decrypt selects the decryption direction (OpenSSL::Cipher#decrypt).
func (c *Cipher) Decrypt() *Cipher { c.encrypt, c.dirSet = false, true; return c }

// SetKey sets the symmetric key. It returns an error if the length does not
// match the cipher's key size, matching MRI's "key length too short/long".
// Validating the length here means aes.NewCipher can never fail later.
func (c *Cipher) SetKey(key []byte) error {
	if len(key) != c.spec.keyLen {
		return cipherError("key length too short")
	}
	// aes.NewCipher only errors on a bad key length, already excluded above.
	block, _ := aes.NewCipher(key)
	c.key = append([]byte(nil), key...)
	c.block = block
	c.resetStream()
	return nil
}

// SetIV sets the initialisation vector / nonce. It returns an error if the
// length is wrong for the mode.
func (c *Cipher) SetIV(iv []byte) error {
	if len(iv) != c.IVLen() {
		return cipherError("iv length too short")
	}
	c.iv = append([]byte(nil), iv...)
	c.resetStream()
	return nil
}

// SetAuthData sets the additional authenticated data for GCM (auth_data=). It
// errors on a non-AEAD cipher, matching MRI.
func (c *Cipher) SetAuthData(aad []byte) error {
	if c.spec.mode != modeGCM {
		return cipherError("AEAD not supported by this cipher")
	}
	c.aad = append([]byte(nil), aad...)
	return nil
}

// SetAuthTag sets the expected GCM tag before decryption (auth_tag=). It errors
// on a non-AEAD cipher.
func (c *Cipher) SetAuthTag(tag []byte) error {
	if c.spec.mode != modeGCM {
		return cipherError("AEAD not supported by this cipher")
	}
	c.authTag = append([]byte(nil), tag...)
	return nil
}

// AuthTag returns the GCM authentication tag produced by Final on encryption.
// It errors if called before Final or on a non-AEAD cipher.
func (c *Cipher) AuthTag() ([]byte, error) {
	if c.spec.mode != modeGCM {
		return nil, cipherError("AEAD not supported by this cipher")
	}
	if c.authTag == nil {
		return nil, cipherError("auth_tag not available")
	}
	return append([]byte(nil), c.authTag...), nil
}

// resetStream discards any streaming state so a fresh key/iv re-initialises it.
func (c *Cipher) resetStream() {
	c.stream = nil
	c.cbc = nil
	c.buf = nil
	c.gcmData = nil
}

// ensureReady validates that a direction, key and IV have been set.
func (c *Cipher) ensureReady() error {
	if !c.dirSet {
		return cipherError("cipher not initialized: call encrypt or decrypt first")
	}
	if c.key == nil {
		return cipherError("key not set")
	}
	if c.iv == nil {
		return cipherError("iv not set")
	}
	return nil
}

// Update feeds data through the cipher and returns the bytes produced so far.
// For CBC/CTR the result streams (CBC emits only whole blocks, buffering the
// remainder); for GCM the data is buffered and emitted whole in Final.
func (c *Cipher) Update(data []byte) ([]byte, error) {
	if err := c.ensureReady(); err != nil {
		return nil, err
	}
	switch c.spec.mode {
	case modeCTR:
		if c.stream == nil {
			c.stream = cipher.NewCTR(c.block, c.iv)
		}
		out := make([]byte, len(data))
		c.stream.XORKeyStream(out, data)
		return out, nil
	case modeGCM:
		c.gcmData = append(c.gcmData, data...)
		return []byte{}, nil
	default: // CBC
		return c.updateCBC(c.block, data)
	}
}

// updateCBC streams CBC: it appends data to the residual buffer and emits every
// complete block, keeping the trailing partial block for Final's padding.
func (c *Cipher) updateCBC(block cipher.Block, data []byte) ([]byte, error) {
	if c.cbc == nil {
		if c.encrypt {
			c.cbc = cipher.NewCBCEncrypter(block, c.iv)
		} else {
			c.cbc = cipher.NewCBCDecrypter(block, c.iv)
		}
	}
	c.buf = append(c.buf, data...)
	// On decrypt we must retain the final block for unpadding in Final, so we
	// only process complete blocks strictly before the current tail.
	n := (len(c.buf) / aesBlockSize) * aesBlockSize
	if !c.encrypt && n == len(c.buf) && n > 0 {
		n -= aesBlockSize
	}
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	c.cbc.CryptBlocks(out, c.buf[:n])
	c.buf = append([]byte(nil), c.buf[n:]...)
	return out, nil
}

// Final completes the operation: it applies/removes PKCS7 padding (CBC),
// computes/verifies the tag (GCM), or returns nothing (CTR), matching MRI.
func (c *Cipher) Final() ([]byte, error) {
	if err := c.ensureReady(); err != nil {
		return nil, err
	}
	switch c.spec.mode {
	case modeCTR:
		return []byte{}, nil
	case modeGCM:
		return c.finalGCM()
	default:
		return c.finalCBC()
	}
}

// finalCBC pads (encrypt) or unpads (decrypt) the buffered residual block.
func (c *Cipher) finalCBC() ([]byte, error) {
	if c.encrypt {
		padded := pkcs7Pad(c.buf, aesBlockSize)
		out := make([]byte, len(padded))
		c.cbc.CryptBlocks(out, padded)
		c.buf = nil
		return out, nil
	}
	if len(c.buf) == 0 {
		return nil, cipherError("wrong final block length")
	}
	if len(c.buf)%aesBlockSize != 0 {
		return nil, cipherError("wrong final block length")
	}
	out := make([]byte, len(c.buf))
	c.cbc.CryptBlocks(out, c.buf)
	c.buf = nil
	return pkcs7Unpad(out, aesBlockSize)
}

// finalGCM runs the buffered message through GCM, producing ciphertext+tag on
// encrypt or verifying the tag and producing plaintext on decrypt.
func (c *Cipher) finalGCM() ([]byte, error) {
	// c.block is set by SetKey and the IV length is validated by SetIV (12 for
	// GCM), so NewGCMWithNonceSize cannot fail here.
	gcm, _ := cipher.NewGCMWithNonceSize(c.block, len(c.iv))
	if c.encrypt {
		sealed := gcm.Seal(nil, c.iv, c.gcmData, c.aad)
		ct := sealed[:len(sealed)-gcm.Overhead()]
		c.authTag = append([]byte(nil), sealed[len(sealed)-gcm.Overhead():]...)
		return ct, nil
	}
	if c.authTag == nil {
		return nil, cipherError("auth_tag must be set before final on decrypt")
	}
	sealed := append(append([]byte(nil), c.gcmData...), c.authTag...)
	pt, err := gcm.Open(nil, c.iv, sealed, c.aad)
	if err != nil {
		return nil, cipherError("OpenSSL::Cipher::CipherError")
	}
	return pt, nil
}

// pkcs7Pad appends PKCS#7 padding to bring data up to a block multiple. A
// full padding block is added when data is already aligned, matching OpenSSL.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad removes and validates PKCS#7 padding, erroring on a malformed pad
// (bad final block) as MRI does.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, cipherError("bad decrypt")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, cipherError("bad decrypt")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, cipherError("bad decrypt")
		}
	}
	return data[:len(data)-pad], nil
}
