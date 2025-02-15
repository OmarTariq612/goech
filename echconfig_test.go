package goech

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

const (
	kemConst = hpke.KEM_X25519_HKDF_SHA256
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
		KEM:           kemConst,
		PublicKey:     publicKey,
		CipherSuites:  allHpkeSymmetricCipherSuite,
		MaxNameLength: 0,
		RawExtensions: nil,
	}

	two := ECHConfig{
		Version:       DraftTLSESNI16,
		ConfigID:      1,
		RawPublicName: []byte("example.com"),
		KEM:           kemConst,
		PublicKey:     publicKey,
		CipherSuites:  allHpkeSymmetricCipherSuite,
		MaxNameLength: 0,
		RawExtensions: []byte{},
	}

	if !one.Equal(&two) {
		t.Fatal("one does not equal two")
	}
}

func TestECHConfigMarshalBinary(t *testing.T) {
	config := ECHConfig{
		Version:   DraftTLSESNI16,
		ConfigID:  1,
		KEM:       kemConst,
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
			KEM:       kemConst,
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
			KEM:       kemConst,
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

func TestCompatiblityWithStdlib(t *testing.T) {
	certificate, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	const (
		outerSNI = "outer.example.com"
		innerSNI = "inner.example.com"
	)

	echConfig1 := ECHConfig{
		PublicKey:     publicKey,
		Version:       DraftTLSESNI16,
		ConfigID:      1,
		RawPublicName: []byte(outerSNI),
		KEM:           hpke.KEM_X25519_HKDF_SHA256,
		CipherSuites: []HpkeSymmetricCipherSuite{
			// this kdf is not supported by the stdlib
			// therefore the tls client will pick echConfig2
			{KDF: hpke.KDF_HKDF_SHA512, AEAD: hpke.AEAD_AES256GCM},
		},
	}

	echConfig2 := ECHConfig{
		PublicKey:     publicKey,
		Version:       DraftTLSESNI16,
		ConfigID:      2,
		RawPublicName: []byte(outerSNI),
		KEM:           hpke.KEM_X25519_HKDF_SHA256,
		CipherSuites: []HpkeSymmetricCipherSuite{
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES256GCM},
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_ChaCha20Poly1305},
		},
	}

	var echConfigList ECHConfigList
	echConfigList = append(echConfigList, echConfig1, echConfig2)
	echConfigListBytes, err := echConfigList.MarshalBinary()

	echConfigBytes, err := echConfig2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()

	clientTLSConn := tls.Client(clientConn, &tls.Config{
		EncryptedClientHelloConfigList: echConfigListBytes,
		ServerName:                     innerSNI,
		InsecureSkipVerify:             true,
	})

	serverTLSConn := tls.Server(serverConn, &tls.Config{
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{Config: echConfigBytes, PrivateKey: privateKeyBytes},
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.ServerName != innerSNI {
				return fmt.Errorf("expected: %s, found: %s", innerSNI, state.ServerName)
			}
			return nil
		},
		Certificates: []tls.Certificate{certificate},
	})

	t.Cleanup(func() {
		_ = clientTLSConn.Close()
		_ = serverTLSConn.Close()
	})

	errc := make(chan error, 2)

	go func() {
		err := clientTLSConn.Handshake()
		if err != nil {
			err = fmt.Errorf("client: %w", err)
		}
		errc <- err
	}()

	go func() {
		err := serverTLSConn.Handshake()
		if err != nil {
			err = fmt.Errorf("server: %w", err)
		}
		errc <- err
	}()

	err = <-errc
	if err != nil {
		t.Fatal(err)
	}
}

func selfSignedCert() (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail(err)
	}

	// Create a certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fail(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Company"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"example.org"},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fail(err)
	}

	// Encode the certificate and private key as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fail(err)
	}

	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	// Create a tls.Certificate
	return tls.X509KeyPair(certPEM, keyPEMBytes)
}
