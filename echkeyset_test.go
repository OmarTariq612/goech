package goech

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func TestECHKeySetEqual(t *testing.T) {
	one := ECHKeySet{
		PrivateKey: privateKey,
		ECHConfig: ECHConfig{
			PublicKey:     publicKey,
			Version:       DraftTLSESNI16,
			ConfigID:      1,
			RawPublicName: []byte("example.com"),
			KEM:           kemConst,
			CipherSuites:  allHpkeSymmetricCipherSuite,
			MaxNameLength: 0,
			RawExtensions: nil,
		},
	}

	two := ECHKeySet{
		PrivateKey: privateKey,
		ECHConfig: ECHConfig{
			PublicKey:     publicKey,
			Version:       DraftTLSESNI16,
			ConfigID:      1,
			RawPublicName: []byte("example.com"),
			KEM:           kemConst,
			CipherSuites:  allHpkeSymmetricCipherSuite,
			MaxNameLength: 0,
			RawExtensions: nil,
		},
	}

	if !one.Equal(&two) {
		t.Fatal("one does not equal two")
	}
}

func TestECHKeySetMarshalBinary(t *testing.T) {
	keySet, err := GenerateECHKeySet(1, "example.com", hpke.KEM_X25519_HKDF_SHA256)
	if err != nil {
		t.Fatal(err)
	}

	bytes1, err := keySet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	newKeySet := &ECHKeySet{}
	if err = newKeySet.UnmarshalBinary(bytes1); err != nil {
		t.Fatal(err)
	}

	if !keySet.Equal(newKeySet) {
		t.Fatal("new one does not equal old one")
	}

	bytes2, err := newKeySet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("bytes aren't equal")
	}
}
