package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

const (
	outerSNI = "outer.example.com"
	innerSNI = "inner.example.com"
)

func main() {
	echKeySet, err := goech.GenerateECHKeySet(1, outerSNI, hpke.KEM_X25519_HKDF_SHA256, []goech.HpkeSymmetricCipherSuite{
		{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
		{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES256GCM},
		{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_ChaCha20Poly1305},
	})
	if err != nil {
		panic(err)
	}

	privateKeyBytes, err := echKeySet.PrivateKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	echConfigBytes, err := echKeySet.ECHConfig.MarshalBinary()
	if err != nil {
		panic(err)
	}

	var echConfigList goech.ECHConfigList
	echConfigList = append(echConfigList, echKeySet.ECHConfig)
	echConfigListBytes, err := echConfigList.MarshalBinary()
	if err != nil {
		panic(err)
	}

	certificate, err := selfSignedCert()
	if err != nil {
		panic(err)
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

	defer func() {
		_ = clientTLSConn.Close()
		_ = serverTLSConn.Close()
	}()

	errc := make(chan error, 2)

	go func() {
		clientTLSConn.SetDeadline(time.Now().Add(5 * time.Second))
		err := clientTLSConn.Handshake()
		if err != nil {
			err = fmt.Errorf("client: %w", err)
		}
		errc <- err
	}()

	go func() {
		serverTLSConn.SetDeadline(time.Now().Add(5 * time.Second))
		err := serverTLSConn.Handshake()
		if err != nil {
			err = fmt.Errorf("server: %w", err)
		}
		errc <- err
	}()

	err = <-errc
	if err != nil {
		panic(err)
	}

	fmt.Println("Handshake was done successfully!")
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

var (
	_ encoding.BinaryAppender = goech.ECHConfig{}
	_ encoding.BinaryAppender = (goech.ECHConfigList)(nil)
)
