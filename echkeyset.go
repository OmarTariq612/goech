package goech

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/binary"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/cryptobyte"
)

func GenerateKeyPair(kem hpke.KEM) (kem.PublicKey, kem.PrivateKey, error) {
	return kem.Scheme().GenerateKeyPair()
}

type ECHKeySet struct {
	PrivateKey kem.PrivateKey
	ECHConfig  ECHConfig
}

func (key *ECHKeySet) String() string {
	return key.ECHConfig.String()
}

func (key *ECHKeySet) Equal(other *ECHKeySet) bool {
	privateKey, err := key.PrivateKey.MarshalBinary()
	if err != nil {
		return false
	}
	otherPrivateKey, err := other.PrivateKey.MarshalBinary()
	if err != nil {
		return false
	}

	return key.ECHConfig.Equal(&other.ECHConfig) && bytes.Equal(privateKey, otherPrivateKey)
}

var (
	_ encoding.BinaryMarshaler   = (*ECHKeySet)(nil)
	_ encoding.BinaryUnmarshaler = (*ECHKeySet)(nil)
)

func (key *ECHKeySet) marchalBinary(b *cryptobyte.Builder) error {
	sk, err := key.PrivateKey.MarshalBinary()
	if err != nil {
		return err
	}
	// length + config
	configBytes, err := key.ECHConfig.MarshalBinary()
	if err != nil {
		return err
	}

	b.AddUint16(uint16(len(sk)))
	b.AddBytes(sk)
	b.AddBytes(configBytes)

	return nil
}

// len -  privatekey - len - config
func (key *ECHKeySet) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	if err := key.marchalBinary(&b); err != nil {
		return nil, err
	}
	return b.Bytes()
}

func (key *ECHKeySet) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	var (
		sk, config cryptobyte.String
	)
	if !s.ReadUint16LengthPrefixed(&sk) || !s.ReadUint16LengthPrefixed(&config) || !s.Empty() {
		// return fmt.Errorf("error parsing key")
		return ErrInvalidLen
	}

	var err error
	if err = key.ECHConfig.unmarshalBinaryConfigOnly(config); err != nil {
		return err
	}
	key.PrivateKey, err = key.ECHConfig.KEM.Scheme().UnmarshalBinaryPrivateKey(sk)

	return err
}

func (key *ECHKeySet) ToBase64() (string, error) {
	data, err := key.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (key *ECHKeySet) ToBase64OrPanic() string {
	keySetBase64, err := key.ToBase64()
	if err != nil {
		panic(err)
	}
	return keySetBase64
}

func (key *ECHKeySet) FromBase64(keySetBase64 string) error {
	data, err := base64.StdEncoding.DecodeString(keySetBase64)
	if err != nil {
		return err
	}
	return key.UnmarshalBinary(data)
}

type ECHKeySetList []ECHKeySet

func (keysets ECHKeySetList) Equal(other ECHKeySetList) bool {
	if len(keysets) != len(other) {
		return false
	}
	for i := range keysets {
		if !keysets[i].Equal(&other[i]) {
			return false
		}
	}
	return true
}

var (
	_ encoding.BinaryMarshaler   = (ECHKeySetList)(nil)
	_ encoding.BinaryUnmarshaler = (*ECHConfigList)(nil)
)

func (keysets ECHKeySetList) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	for _, keySet := range keysets {
		if err := keySet.marchalBinary(&b); err != nil {
			return nil, err
		}
	}
	return b.Bytes()
}

func (keysets *ECHKeySetList) UnmarshalBinary(data []byte) error {
	*keysets = (*keysets)[:0]
	s := cryptobyte.String(data)

	var keyset ECHKeySet

	for !s.Empty() {
		if len(s) < 2 {
			return ErrInvalidLen
		}
		keyLength := int(binary.BigEndian.Uint16(s[:2]))
		if len(s) < keyLength+4 {
			return ErrInvalidLen
		}
		configLength := int(binary.BigEndian.Uint16(s[keyLength+2 : keyLength+4]))
		if len(s) < 2+keyLength+2+configLength {
			return ErrInvalidLen
		}
		if err := keyset.UnmarshalBinary(s[:2+keyLength+2+configLength]); err != nil {
			return err
		}
		if !s.Skip(2 + keyLength + 2 + configLength) {
			return ErrInvalidLen
		}
		*keysets = append(*keysets, keyset)
	}

	return nil
}

func (keysets ECHKeySetList) ToBase64() (string, error) {
	data, err := keysets.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (keysets ECHKeySetList) ToBase64OrPanic() string {
	keySetListBase64, err := keysets.ToBase64()
	if err != nil {
		panic(err)
	}
	return keySetListBase64
}

func (keysets *ECHKeySetList) FromBase64(keySetListBase64 string) error {
	data, err := base64.StdEncoding.DecodeString(keySetListBase64)
	if err != nil {
		return err
	}
	return keysets.UnmarshalBinary(data)
}

func MarshalECHKeySetList(keysets []ECHKeySet) ([]byte, error) {
	return ECHKeySetList(keysets).MarshalBinary()
}

func MarshalECHKeySetArgs(keysets ...ECHKeySet) ([]byte, error) {
	return MarshalECHKeySetList(keysets)
}

func UnmarshalECHKeySetList(data []byte) (ECHKeySetList, error) {
	c := ECHKeySetList{}
	err := c.UnmarshalBinary(data)
	return c, err
}

func ECHKeySetListFromBase64(echKeySetListBase64 string) (ECHKeySetList, error) {
	data, err := base64.StdEncoding.DecodeString(echKeySetListBase64)
	if err != nil {
		return nil, err
	}
	return UnmarshalECHKeySetList(data)
}

func GenerateECHKeySet(configID uint8, domain string, kem hpke.KEM) (*ECHKeySet, error) {
	publicKey, privateKey, err := GenerateKeyPair(kem)
	if err != nil {
		return nil, err
	}

	return &ECHKeySet{
		PrivateKey: privateKey,
		ECHConfig: ECHConfig{
			PublicKey:     publicKey,
			Version:       DraftTLSESNI16,
			ConfigID:      configID,
			RawPublicName: []byte(domain),
			KEM:           kem,
			CipherSuites:  allHpkeSymmetricCipherSuite,
			MaxNameLength: 0,
			RawExtensions: nil,
		},
	}, nil
}
