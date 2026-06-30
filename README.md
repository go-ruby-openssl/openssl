<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-openssl/brand/main/social/go-ruby-openssl-openssl.png" alt="go-ruby-openssl/openssl" width="720"></p>

# openssl — go-ruby-openssl

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#testing--parity)
[![CGO](https://img.shields.io/badge/cgo-0-success)](#design)

**A pure-Go (no cgo) reimplementation of Ruby's `OpenSSL` standard library**,
built over Go's `crypto/*` packages instead of linking `libcrypto`. The
C-binding surface Ruby's MRI extension exposes is re-expressed entirely in Go
standard-library crypto, so the result is a **static, CGO-free** library that
still matches MRI **byte-for-byte** wherever Go's crypto allows it.

It is the OpenSSL backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby) (rbgo), replacing
and extending its in-VM `openssl.go` shim, but it is a **standalone, reusable**
module with no dependency on the Ruby runtime.

## Design

| MRI namespace                       | Backend                              |
| ----------------------------------- | ------------------------------------ |
| `OpenSSL::Digest`                   | `crypto/md5,sha1,sha256,sha512`      |
| `OpenSSL::HMAC`                     | `crypto/hmac`                        |
| `OpenSSL::Cipher` (AES CBC/GCM/CTR) | `crypto/aes` + `crypto/cipher`       |
| `OpenSSL::PKCS5` / `OpenSSL::KDF`   | `crypto/pbkdf2`, `crypto/hkdf`, `x/crypto/scrypt` |
| `OpenSSL::Random`                   | `crypto/rand`                        |
| `OpenSSL::ASN1`                     | hand-rolled DER over `math/big`      |
| `OpenSSL::BN`                       | `math/big`                           |
| `OpenSSL::X509::{Certificate,Name}` | `crypto/x509` + `encoding/pem`       |
| `OpenSSL::PKey::{RSA,EC}`           | `crypto/rsa`, `crypto/ecdsa`         |
| `OpenSSL::SSL::SSLContext`          | config model → `crypto/tls.Config`   |

## Boundary: IN / Go-crypto seam / OUT

**IN — real crypto, MRI-faithful, byte-exact:**

- **Digest** — MD5, SHA1, SHA224, SHA256, SHA384, SHA512; streaming
  (`Update`/`Reset`) and one-shot (`HexDigest(name, data)`), dashed/lowercase
  names, `digest`/`hexdigest`/`base64digest`.
- **HMAC** — over any supported digest; streaming and one-shot.
- **Cipher** — AES-128/192/256 in **CBC** (PKCS7 padding), **GCM** (auth tag +
  AAD), and **CTR**; full `encrypt`/`decrypt`/`key=`/`iv=`/`update`/`final`/
  `auth_tag`/`auth_data` lifecycle.
- **KDF** — `PBKDF2HMAC`, `SCrypt`, `HKDF`.
- **Random** — `RandomBytes` / `PseudoBytes`.
- **ASN.1** — DER encode/decode of BOOLEAN, INTEGER, ENUMERATED, NULL, OCTET
  STRING, BIT STRING, OBJECT IDENTIFIER, UTF8String, SEQUENCE, SET — including
  MRI's unsigned-INTEGER leading-zero rule and multi-byte OID subidentifiers.
- **BN** — arbitrary-precision integers (`+ - * mod cmp num_bits num_bytes`,
  decimal/upper-hex `to_s`).
- **X509** — parse PEM/DER certificates and read `subject`/`issuer`/`serial`/
  `version`/`not_before`/`not_after`/`public_key`/`signature_algorithm`;
  `Name` parse/`to_s`/`to_der` (ordered RDNs, UTF8String — byte-identical to
  MRI); **self-signed** certificate generation.
- **PKey** — RSA and EC key **parse** (PKCS#1/PKCS#8/SEC1/PKIX PEM),
  **generate**, **sign** and **verify** (RSA PKCS#1 v1.5, ECDSA).

**Go-crypto SEAM — modelled here, driven by the host:**

- **`SSLContext`** captures the configuration half of `OpenSSL::SSL::SSLContext`
  (verify mode, protocol-version bounds, SNI, trust store, local identity) and
  lowers it to a `*tls.Config` via `ToTLSConfig`. The **live TLS handshake** is
  performed by the host with `crypto/tls`; this package builds configuration
  only and opens no sockets.

**OUT of scope:**

- OpenSSL engines, legacy/deprecated ciphers (DES, RC4, Blowfish), PKCS#12,
  OCSP, CRL signing, netscape-SPKI, and full X.509 **chain path validation**
  beyond what `crypto/x509` exposes.

## Usage

```go
import openssl "github.com/go-ruby-openssl/openssl"

// Digest
h, _ := openssl.HexDigest("SHA256", []byte("abc"))         // ba7816bf...

// HMAC
m, _ := openssl.HMACHexDigest("SHA256", []byte("key"), []byte("data"))

// AES-256-GCM
c, _ := openssl.NewCipher("aes-256-gcm")
c.Encrypt(); c.SetKey(key); c.SetIV(nonce); c.SetAuthData(aad)
ct, _ := c.Update(plaintext)
fin, _ := c.Final()
tag, _ := c.AuthTag()

// PBKDF2 / scrypt / HKDF
k, _ := openssl.PBKDF2HMAC([]byte("password"), []byte("salt"), 1000, 32, "SHA256")

// X.509
cert, _ := openssl.ParseCertificate(pemBytes)
_ = cert.Subject().String()                                // /CN=example.com/O=Acme

// SSL context (config model)
ctx := openssl.NewSSLContext()
ctx.VerifyMode = openssl.VerifyPeer
cfg, _ := ctx.ToTLSConfig()                                // host drives crypto/tls
```

## Testing & parity

Every algorithm is checked against a **MRI oracle vector** captured from
`ruby -ropenssl` (4.0.0) — digests, HMAC, AES (CBC/GCM/CTR), PBKDF2, scrypt,
HKDF, ASN.1 DER, X.509 `Name` DER — plus committed PEM/DER fixtures for the
PKey/X509 parse paths. The suite is **deterministic and ruby-free**, so it runs
identically on Linux, macOS and Windows, under `-race`, and across all six
supported 64-bit architectures (amd64, arm64, riscv64, loong64, ppc64le,
s390x). **Coverage is 100%**, error branches included.

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-openssl/openssl
authors.
