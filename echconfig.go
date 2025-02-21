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

// ECHConfig represents an Encrypted Client Hello configuration.
//
// Encoding is done according to the ECHConfig struct defined in the draft-ietf-tls-esni-22.
// It also matches `tls.Config.EncryptedClientHelloKeys.Config` in the Go standard library.
type ECHConfig struct {
	// The version of the ECHConfig struct.
	Version uint16

	// A one-byte identifier for the given HPKE key configuration.
	// This is used by clients to indicate the key used for ClientHello encryption.
	//
	// Section 4.1 describes how client-facing servers allocate this value.
	ConfigID uint8

	// The HPKE KEM identifier corresponding to public_key.
	// Clients MUST ignore any ECHConfig structure with a key using a KEM they do not support
	KEM hpke.KEM

	// The HPKE public key used by the client to encrypt ClientHelloInner.
	PublicKey kem.PublicKey

	// The list of HPKE KDF and AEAD identifier pairs clients can use for encrypting ClientHelloInner.
	//
	// See Section 6.1 for how clients choose from this list.
	CipherSuites []HpkeSymmetricCipherSuite

	// The longest name of a backend server, if known. If not known, this value can be set to zero.
	//
	// It is used to compute padding (Section 6.1.3) and does not constrain server name lengths.
	// Names may exceed this length if, e.g., the server uses wildcard names or added new names to the anonymity set.
	MaxNameLength uint8

	// The DNS name of the client-facing server, i.e., the entity trusted to update the ECH configuration.
	//
	// This is used to correct misconfigured clients, as described in Section 6.1.6.
	RawPublicName []byte

	// A list of ECHConfigExtension values that the client must take into consideration when generating a ClientHello message.
	//
	// Each ECHConfigExtension has a 2-octet type and opaque data value,
	// where the data value is encoded with a 2-octet integer representing the length of the data, in network byte order.
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

	return ech.Version == other.Version && ech.ConfigID == other.ConfigID && ech.MaxNameLength == other.MaxNameLength && bytes.Equal(ech.RawPublicName, other.RawPublicName) && bytes.Equal(echPublicKey, otherPublicKey) && bytes.Equal(ech.RawExtensions, other.RawExtensions)
}

var (
	_ encoding.BinaryMarshaler = ECHConfig{}
	// _ encoding.BinaryAppender    = ECHConfig{}
	_ encoding.BinaryUnmarshaler = (*ECHConfig)(nil)
)

func (ech ECHConfig) marshalBinaryImpl(b *cryptobyte.Builder) error {
	pk, err := ech.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	if l := len(ech.RawPublicName); l == 0 || l > 255 {
		return InvalidPublicNameLenError(l)
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
	var b cryptobyte.Builder

	if err := ech.marshalBinaryImpl(&b); err != nil {
		return nil, err
	}

	return b.Bytes()
}

func (ech ECHConfig) AppendBinary(b []byte) ([]byte, error) {
	cbb := cryptobyte.NewBuilder(b)
	if err := ech.marshalBinaryImpl(cbb); err != nil {
		return nil, err
	}
	return cbb.Bytes()
}

func (ech *ECHConfig) unmarshalBinaryImpl(data []byte) error {
	var content cryptobyte.String
	b := cryptobyte.String(data)

	if !b.ReadUint16(&ech.Version) {
		return ErrInvalidLen
	}
	if ech.Version != DraftTLSESNI16 {
		return ErrNotSupportedVersion
	}

	if !b.ReadUint16LengthPrefixed(&content) || !b.Empty() {
		return ErrInvalidLen
	}

	var t cryptobyte.String
	var pk []byte

	if !content.ReadUint8(&ech.ConfigID) ||
		!content.ReadUint16((*uint16)(&ech.KEM)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&pk, len(t)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 /* the length of (KDFs and AEADs) must be divisible by 4 */ {
		return ErrInvalidLen
	}

	if !ech.KEM.IsValid() {
		return InvalidKEMError(ech.KEM)
	}

	var err error
	if ech.PublicKey, err = ech.KEM.Scheme().UnmarshalBinaryPublicKey(pk); err != nil {
		return fmt.Errorf("parsing public_key: %w", err)
	}

	ech.CipherSuites = ech.CipherSuites[:0]

	for !t.Empty() {
		var hpkeKDF, hpkeAEAD uint16
		if !t.ReadUint16(&hpkeKDF) || !t.ReadUint16(&hpkeAEAD) {
			// we have already checked that the length is divisible by 4
			panic("this must not happen")
		}
		if !hpke.KDF(hpkeKDF).IsValid() {
			return InvalidKDFError(hpkeKDF)
		}
		if !hpke.AEAD(hpkeAEAD).IsValid() {
			return InvalidAEADError(hpkeAEAD)
		}
		ech.CipherSuites = append(ech.CipherSuites, HpkeSymmetricCipherSuite{KDF: hpke.KDF(hpkeKDF), AEAD: hpke.AEAD(hpkeAEAD)})
	}

	if !content.ReadUint8(&ech.MaxNameLength) ||
		!content.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.RawPublicName, len(t)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.RawExtensions, len(t)) ||
		!content.Empty() {
		return ErrInvalidLen
	}

	return nil
}

func (ech *ECHConfig) UnmarshalBinary(data []byte) error {
	return ech.unmarshalBinaryImpl(data)
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

// The ECHConfigList structure contains one or more ECHConfig structures in decreasing order of preference.
// This allows a server to support multiple versions of ECH and multiple sets of ECH parameters.
//
// Encoding is done according to the ECHConfigList type defined in the draft-ietf-tls-esni-22.
// It also matches `tls.Config.EncryptedClientHelloConfigList` in the Go standard library.
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
	_ encoding.BinaryMarshaler = (ECHConfigList)(nil)
	// _ encoding.BinaryAppender    = (ECHConfigList)(nil)
	_ encoding.BinaryUnmarshaler = (*ECHConfigList)(nil)
)

func (configs ECHConfigList) MarshalBinary() ([]byte, error) {
	var (
		b   cryptobyte.Builder
		err error
	)

	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for _, echConfig := range configs {
			err = echConfig.marshalBinaryImpl(child)
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

func (configs ECHConfigList) AppendBinary(b []byte) ([]byte, error) {
	cbb := cryptobyte.NewBuilder(b)

	var err error

	cbb.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		for _, echConfig := range configs {
			err = echConfig.marshalBinaryImpl(child)
			if err != nil {
				break
			}
		}
	})

	if err != nil {
		return nil, err
	}

	return cbb.Bytes()
}

func (configs *ECHConfigList) UnmarshalBinary(data []byte) error {
	*configs = (*configs)[:0] // here we are using the cap only, if there was a previous list, Unmarshal is gonna write over it
	var (
		err error
		t   cryptobyte.String
	)
	s := cryptobyte.String(data)
	if !s.ReadUint16LengthPrefixed(&t) || !s.Empty() {
		return ErrInvalidLen
	}

	for !t.Empty() {
		if len(t) < 4 {
			return ErrInvalidLen
		}
		length := int(binary.BigEndian.Uint16(t[2:4]))
		if len(t) < length+4 {
			return ErrInvalidLen
		}
		var config ECHConfig
		err = config.UnmarshalBinary(t[:length+4])
		if err != nil {
			return err
		}
		if !t.Skip(length + 4) {
			return ErrInvalidLen
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

func MarshalECHConfigList(configs []ECHConfig) ([]byte, error) {
	return ECHConfigList(configs).MarshalBinary()
}

func MarshalECHConfigArgs(configs ...ECHConfig) ([]byte, error) {
	return MarshalECHConfigList(configs)
}

func UnmarshalECHConfigList(data []byte) (configList ECHConfigList, err error) {
	err = configList.UnmarshalBinary(data)
	return configList, err
}

func ECHConfigListFromBase64(echConfigListBase64 string) (ECHConfigList, error) {
	data, err := base64.StdEncoding.DecodeString(echConfigListBase64)
	if err != nil {
		return nil, err
	}
	return UnmarshalECHConfigList(data)
}
