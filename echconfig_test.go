package goech

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/cryptobyte"
)

const (
	kemConst = hpke.KEM_P256_HKDF_SHA256
)

var (
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
)

func TestMain(m *testing.M) {
	var err error
	publicKey, privateKey, err = kemConst.Scheme().GenerateKeyPair()
	if err != nil {
		log.Fatalf("ERR: %v\n", err.Error())
	}

	os.Exit(m.Run())
}

func TestECHConfigEqual(t *testing.T) {
	one := ECHConfig{
		Version:       DraftTLSESNI16,
		ConfigID:      1,
		RawPublicName: []byte("example.com"),
		KEM:           hpke.KEM_P256_HKDF_SHA256,
		PublicKey:     publicKey,
		CipherSuites:  allHpkeSymmetricCipherSuite,
		MaxNameLength: 0,
		RawExtensions: nil,
	}

	two := ECHConfig{
		Version:       DraftTLSESNI16,
		ConfigID:      1,
		RawPublicName: []byte("example.com"),
		KEM:           hpke.KEM_P256_HKDF_SHA256,
		PublicKey:     publicKey,
		CipherSuites:  allHpkeSymmetricCipherSuite,
		MaxNameLength: 0,
		RawExtensions: []byte{},
	}

	if !one.Equal(&two) {
		t.Fatal("one does not equal two")
	}
}

func TestMarshalBinaryOnlyConfig(t *testing.T) {
	config := ECHConfig{
		Version:   DraftTLSESNI16,
		ConfigID:  1,
		KEM:       hpke.KEM_P256_HKDF_SHA256,
		PublicKey: publicKey,
		CipherSuites: []HpkeSymmetricCipherSuite{
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
		},
		MaxNameLength: 0,
		RawPublicName: []byte("example.com"),
		RawExtensions: nil,
	}

	var b1 cryptobyte.Builder
	if err := config.marshalBinaryOnlyConfig(&b1); err != nil {
		t.Fatal(err)
	}
	bytes1, err := b1.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	var newConfig ECHConfig
	if err := newConfig.unmarshalBinaryConfigOnly(bytes1); err != nil {
		t.Fatal(err)
	}

	if !config.Equal(&newConfig) {
		t.Fatal("new one does not equal old one")
	}

	var b2 cryptobyte.Builder
	if err := newConfig.marshalBinaryOnlyConfig(&b2); err != nil {
		t.Fatal(err)
	}
	bytes2, err := b2.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("bytes are not equal")
	}
}

func TestECHConfigMarshalBinary(t *testing.T) {
	config := ECHConfig{
		Version:   DraftTLSESNI16,
		ConfigID:  1,
		KEM:       hpke.KEM_P256_HKDF_SHA256,
		PublicKey: publicKey,
		CipherSuites: []HpkeSymmetricCipherSuite{
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
		},
		MaxNameLength: 0,
		RawPublicName: []byte("example.com"),
		RawExtensions: nil,
	}

	bytes1, err := config.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var newConfig ECHConfig
	if err = newConfig.UnmarshalBinary(bytes1); err != nil {
		t.Fatal(err)
	}

	if !config.Equal(&newConfig) {
		t.Fatal("new one does not equal old one")
	}

	bytes2, err := newConfig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("bytes aren't equal")
	}
}

func TestECHConfigListMarshalBinary(t *testing.T) {
	configList := ECHConfigList{
		ECHConfig{
			Version:   DraftTLSESNI16,
			ConfigID:  1,
			KEM:       hpke.KEM_P256_HKDF_SHA256,
			PublicKey: publicKey,
			CipherSuites: []HpkeSymmetricCipherSuite{
				{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
			},
			MaxNameLength: 0,
			RawPublicName: []byte("example.com"),
			RawExtensions: nil,
		},

		ECHConfig{
			Version:   DraftTLSESNI16,
			ConfigID:  2,
			KEM:       hpke.KEM_P256_HKDF_SHA256,
			PublicKey: publicKey,
			CipherSuites: []HpkeSymmetricCipherSuite{
				{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_ChaCha20Poly1305},
			},
			MaxNameLength: 0,
			RawPublicName: []byte("example.org"),
			RawExtensions: nil,
		},
	}

	bytes1, err := configList.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var newConfigList ECHConfigList
	if err = newConfigList.UnmarshalBinary(bytes1); err != nil {
		t.Fatal(err)
	}

	if !configList.Equal(newConfigList) {
		t.Fatal("new one does not equal old one")
	}

	bytes2, err := newConfigList.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("bytes aren't equal")
	}
}

func TestUnmarshalECHConfigList(t *testing.T) {
	publicKey1, _, err := GenerateKeyPair(hpke.KEM_P256_HKDF_SHA256)
	if err != nil {
		t.Fatal(err)
	}

	publicKey2, _, err := GenerateKeyPair(hpke.KEM_P521_HKDF_SHA512)
	if err != nil {
		t.Fatal(err)
	}

	list := ECHConfigList{
		{RawPublicName: []byte("one.example.com"), PublicKey: publicKey1, Version: DraftTLSESNI16, KEM: hpke.KEM_P256_HKDF_SHA256, RawExtensions: []byte{1, 2, 3}},
		{RawPublicName: []byte("two.example.com"), PublicKey: publicKey2, Version: DraftTLSESNI16, KEM: hpke.KEM_P521_HKDF_SHA512, RawExtensions: []byte{4, 5, 6}},
	}

	rawList, err := list.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	unmarshaledList, err := UnmarshalECHConfigList(rawList)
	if err != nil {
		t.Fatal(err)
	}

	if !list.Equal(unmarshaledList) {
		t.Fatal("unmarshaled list doesn't equal the original one")
	}
}
