package goech

import "github.com/cloudflare/circl/hpke"

const (
	DraftTLSESNI16 = 0xfe0d
)

var (
	allHpkeSymmetricCipherSuite = []HpkeSymmetricCipherSuite{
		{hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM},
		{hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM},
		{hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305},

		{hpke.KDF_HKDF_SHA384, hpke.AEAD_AES128GCM},
		{hpke.KDF_HKDF_SHA384, hpke.AEAD_AES256GCM},
		{hpke.KDF_HKDF_SHA384, hpke.AEAD_ChaCha20Poly1305},

		{hpke.KDF_HKDF_SHA512, hpke.AEAD_AES128GCM},
		{hpke.KDF_HKDF_SHA512, hpke.AEAD_AES256GCM},
		{hpke.KDF_HKDF_SHA512, hpke.AEAD_ChaCha20Poly1305},
	}

	KDFMapping = [...]string{
		hpke.KDF_HKDF_SHA256: "SHA256",
		hpke.KDF_HKDF_SHA384: "SHA384",
		hpke.KDF_HKDF_SHA512: "SHA512",
	}

	AEADMapping = [...]string{
		hpke.AEAD_AES128GCM:        "AES128GCM",
		hpke.AEAD_AES256GCM:        "AES256GCM",
		hpke.AEAD_ChaCha20Poly1305: "CHACHA20POLY1305",
	}

	KemMapping = [...]string{
		hpke.KEM_P256_HKDF_SHA256:   "P256-SHA256",
		hpke.KEM_P384_HKDF_SHA384:   "P384-SHA384",
		hpke.KEM_P521_HKDF_SHA512:   "P521-SHA512",
		hpke.KEM_X25519_HKDF_SHA256: "X25519-SHA256",
		hpke.KEM_X448_HKDF_SHA512:   "X25519-SHA512",
	}
)
