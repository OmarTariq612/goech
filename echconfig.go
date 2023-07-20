package goech

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/cryptobyte"
)

type HpkeSymmetricCipherSuite struct {
	KDF  hpke.KDF
	AEAD hpke.AEAD
}

func (cipherSuite HpkeSymmetricCipherSuite) String() string {
	return fmt.Sprintf("{(cipher) kdf: %s, aead: %s}", KDFMapping[cipherSuite.KDF], AEADMapping[cipherSuite.AEAD])
}

type ECHConfig struct {
	PublicKey     kem.PublicKey
	Version       uint16
	ConfigID      uint8
	RawPublicName []byte
	KEM           hpke.KEM
	CipherSuites  []HpkeSymmetricCipherSuite
	MaxNameLength uint8
	RawExtensions []byte
}

func (ech ECHConfig) String() string {
	return fmt.Sprintf("{(conf) version: %d, config_id: %d, domain: %s, max_len: %d, kem: %v, cipher_suites: %v}", ech.Version, ech.ConfigID, string(ech.RawPublicName), ech.MaxNameLength, KemMapping[ech.KEM], ech.CipherSuites)
}

func (ech *ECHConfig) Equal(other *ECHConfig) bool {
	if ech.KEM != other.KEM {
		return false
	}
	echPublicKey, err := ech.PublicKey.MarshalBinary()
	if err != nil {
		return false
	}
	otherPublicKey, err := other.PublicKey.MarshalBinary()
	if err != nil {
		return false
	}
	if len(ech.CipherSuites) != len(other.CipherSuites) {
		return false
	}
	for i := range ech.CipherSuites {
		if ech.CipherSuites[i] != other.CipherSuites[i] {
			return false
		}
	}

	return bytes.Equal(echPublicKey, otherPublicKey) && ech.Version == other.Version && ech.ConfigID == other.ConfigID && bytes.Equal(ech.RawPublicName, other.RawPublicName) && ech.MaxNameLength == other.MaxNameLength && bytes.Equal(ech.RawExtensions, other.RawExtensions)
}

var (
	_ encoding.BinaryMarshaler   = ECHConfig{}
	_ encoding.BinaryUnmarshaler = (*ECHConfig)(nil)
)

func (ech ECHConfig) marshalBinaryOnlyConfig(b *cryptobyte.Builder) error {
	pk, err := ech.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	if l := len(ech.RawPublicName); l == 0 || l > 255 {
		return fmt.Errorf("ERR: (len = %d) -> public name length must be 0 < len < 255", l)
	}

	b.AddUint16(ech.Version)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {

		child.AddUint8(ech.ConfigID)
		child.AddUint16(uint16(ech.KEM))
		child.AddUint16(uint16(len(pk)))
		child.AddBytes(pk)

		child.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			for _, cipherSuite := range ech.CipherSuites {
				child.AddUint16(uint16(cipherSuite.KDF))
				child.AddUint16(uint16(cipherSuite.AEAD))
			}
		})

		child.AddUint8(ech.MaxNameLength)
		child.AddUint8(uint8(len(ech.RawPublicName)))
		child.AddBytes(ech.RawPublicName)
		child.AddUint16(uint16(len(ech.RawExtensions)))
		child.AddBytes(ech.RawExtensions)
	})

	return nil
}

func (ech ECHConfig) MarshalBinary() ([]byte, error) {
	var (
		b   cryptobyte.Builder
		err error
	)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		err = ech.marshalBinaryOnlyConfig(child)
	})

	if err != nil {
		return nil, err
	}

	return b.Bytes()
}

func (ech *ECHConfig) unmarshalBinaryConfigOnly(data []byte) error {
	var content cryptobyte.String
	b := cryptobyte.String(data)

	if !b.ReadUint16(&ech.Version) || ech.Version != DraftTLSESNI16 {
		return fmt.Errorf("ERR: invalid ECHConfig")
	}
	if !b.ReadUint16LengthPrefixed(&content) || !b.Empty() {
		return fmt.Errorf("ERR: parsing ECHConfig")
	}

	var t cryptobyte.String
	var pk []byte

	if !content.ReadUint8(&ech.ConfigID) ||
		!content.ReadUint16((*uint16)(&ech.KEM)) ||
		!ech.KEM.IsValid() ||
		!content.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&pk, len(t)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 {
		return fmt.Errorf("ERR: parsing ECHConfigContents")
	}

	var err error
	if ech.PublicKey, err = ech.KEM.Scheme().UnmarshalBinaryPublicKey(pk); err != nil {
		return fmt.Errorf("ERR: parsing public_key: %w", err)
	}

	ech.CipherSuites = nil

	for !t.Empty() {
		var hpkeKDF, hpkeAEAD uint16
		if !t.ReadUint16(&hpkeKDF) || !t.ReadUint16(&hpkeAEAD) {
			panic("this must not happen")
		}
		if !hpke.KDF(hpkeKDF).IsValid() {
			return fmt.Errorf("ERR: invalid kdf id: %d", hpkeKDF)
		}
		if !hpke.AEAD(hpkeAEAD).IsValid() {
			return fmt.Errorf("ERR: invalid aead id: %d", hpkeKDF)
		}
		ech.CipherSuites = append(ech.CipherSuites, HpkeSymmetricCipherSuite{KDF: hpke.KDF(hpkeKDF), AEAD: hpke.AEAD(hpkeAEAD)})
	}

	if !content.ReadUint8(&ech.MaxNameLength) ||
		!content.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.RawPublicName, len(t)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.RawExtensions, len(t)) ||
		!content.Empty() {
		return fmt.Errorf("ERR: parsing ECHConfigContents")
	}

	return nil
}

func (ech *ECHConfig) UnmarshalBinary(data []byte) error {
	b := cryptobyte.String(data)

	var t cryptobyte.String
	if !b.ReadUint16LengthPrefixed(&t) || !b.Empty() {
		return fmt.Errorf("ERR: invalid ECHConfig")
	}

	return ech.unmarshalBinaryConfigOnly(t)
}

type ECHConfigList []ECHConfig

func (configs ECHConfigList) Equal(other ECHConfigList) bool {
	if len(configs) != len(other) {
		return false
	}
	for i := range configs {
		if !configs[i].Equal(&other[i]) {
			return false
		}
	}
	return true
}

var (
	_ encoding.BinaryMarshaler   = (ECHConfigList)(nil)
	_ encoding.BinaryUnmarshaler = (*ECHConfigList)(nil)
)

func (configs ECHConfigList) MarshalBinary() ([]byte, error) {
	var (
		b   cryptobyte.Builder
		err error
	)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for _, echConfig := range configs {
			err = echConfig.marshalBinaryOnlyConfig(child)
			if err != nil {
				break
			}
		}
	})

	if err != nil {
		return nil, err
	}

	return b.Bytes()
}

func (configs *ECHConfigList) UnmarshalBinary(data []byte) error {
	*configs = (*configs)[:0]
	var (
		err    error
		config ECHConfig
		t      cryptobyte.String
	)
	s := cryptobyte.String(data)
	if !s.ReadUint16LengthPrefixed(&t) || !s.Empty() {
		return fmt.Errorf("ERR: parsing ECHConfigList")
	}

	for !t.Empty() {
		if len(t) < 4 {
			return fmt.Errorf("ERR: invalid ECHConfigList")
		}
		length := int(binary.BigEndian.Uint16(t[2:4]))
		if len(t) < length+4 {
			return fmt.Errorf("ERR: invalid ECHConfigList")
		}
		err = config.unmarshalBinaryConfigOnly(t[:length+4])
		if err != nil {
			return err
		}
		if !t.Skip(length + 4) {
			return fmt.Errorf("ERR: parsing ECHConfigList")
		}

		*configs = append(*configs, config)
	}
	return nil
}

func (configs ECHConfigList) ToBase64() (string, error) {
	data, err := configs.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (configs ECHConfigList) ToBase64OrPanic() string {
	echConfigListBase64, err := configs.ToBase64()
	if err != nil {
		panic(err)
	}
	return echConfigListBase64
}

func (configs *ECHConfigList) FromBase64(echConfigListBase64 string) error {
	data, err := base64.StdEncoding.DecodeString(echConfigListBase64)
	if err != nil {
		return err
	}
	return configs.UnmarshalBinary(data)
}

func (ech ECHConfig) ToBase64() (string, error) {
	data, err := ech.MarshalBinary()
	if err != nil {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (ech ECHConfig) ToBase64OrPanic() string {
	echConfigBase64, err := ech.ToBase64()
	if err != nil {
		panic(err)
	}
	return echConfigBase64
}

func (ech *ECHConfig) FromBase64(echConfigBase64 string) error {
	data, err := base64.StdEncoding.DecodeString(echConfigBase64)
	if err != nil {
		return err
	}
	return ech.UnmarshalBinary(data)
}

func MarshalECHConfigList(configs []ECHConfig) ([]byte, error) {
	return ECHConfigList(configs).MarshalBinary()
}

func MarshalECHConfigArgs(configs ...ECHConfig) ([]byte, error) {
	return MarshalECHConfigList(configs)
}

func UnmarshalECHConfigList(data []byte) (ECHConfigList, error) {
	c := ECHConfigList{}
	err := c.UnmarshalBinary(data)
	return c, err
}

func ECHConfigListFromBase64(echConfigListBase64 string) (ECHConfigList, error) {
	data, err := base64.StdEncoding.DecodeString(echConfigListBase64)
	if err != nil {
		return nil, err
	}
	return UnmarshalECHConfigList(data)
}
