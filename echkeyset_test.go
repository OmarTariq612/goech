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
	keySet, err := GenerateECHKeySet(1, "example.com", hpke.KEM_X25519_HKDF_SHA256, nil)
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

func TestECHKeySetListMarshalBinary(t *testing.T) {
	publicKey1, privateKey1, err := GenerateKeyPair(hpke.KEM_P256_HKDF_SHA256)
	if err != nil {
		t.Fatal(err)
	}

	publicKey2, privateKey2, err := GenerateKeyPair(hpke.KEM_P521_HKDF_SHA512)
	if err != nil {
		t.Fatal(err)
	}

	keySetList := ECHKeySetList{
		{
			PrivateKey: privateKey1,
			ECHConfig: ECHConfig{
				PublicKey:     publicKey1,
				Version:       DraftTLSESNI16,
				ConfigID:      1,
				RawPublicName: []byte("example.com"),
				KEM:           hpke.KEM_P256_HKDF_SHA256,
				CipherSuites:  allHpkeSymmetricCipherSuite,
				MaxNameLength: 0,
				RawExtensions: nil,
			},
		},
		{
			PrivateKey: privateKey2,
			ECHConfig: ECHConfig{
				PublicKey:     publicKey2,
				Version:       DraftTLSESNI16,
				ConfigID:      1,
				RawPublicName: []byte("example.org"),
				KEM:           hpke.KEM_P521_HKDF_SHA512,
				CipherSuites:  allHpkeSymmetricCipherSuite,
				MaxNameLength: 0,
				RawExtensions: nil,
			},
		},
	}

	bytes1, err := keySetList.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var newKeySetList ECHKeySetList
	if err = newKeySetList.UnmarshalBinary(bytes1); err != nil {
		t.Fatal(err)
	}

	if len(keySetList) != len(newKeySetList) {
		t.Fatal("new key set list does not have the same length as the old one")
	}

	if !keySetList.Equal(newKeySetList) {
		t.Fatal("new one does not equal old one")
	}

	for i := range keySetList {
		if !keySetList[i].Equal(&newKeySetList[i]) {
			t.Fatal("new one does not equal old one")
		}
	}

	bytes2, err := newKeySetList.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("bytes aren't equal")
	}
}
