package tls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"go.uber.org/zap"
)

// pre built in tls cert
var (
	CertFileName = os.Getenv("STAGENT_CERT_FILE_NAME")
	KeyFileName  = os.Getenv("STAGENT_KEY_FILE_NAME")

	DefaultTLSConfig          *tls.Config
	DefaultTLSConfigCertBytes []byte
	DefaultTLSConfigKeyBytes  []byte
)

func InitTlsCfg() error {
	// If certmagic is active, skip self-signed generation — certificates
	// are managed by certmagic and served via GetCertificate.
	if CertMagicInstance != nil {
		return nil
	}
	if DefaultTLSConfig != nil {
		return nil
	}
	cert, err := genCertificate()
	if err != nil {
		return err
	}
	DefaultTLSConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	return nil
}

// GetCertificate returns a TLS certificate for the given ClientHelloInfo.
// When certmagic is active it delegates to magic.GetCertificate (which handles
// automatic renewal transparently). Otherwise it returns the self-signed
// certificate from DefaultTLSConfig.
func GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if CertMagicInstance != nil {
		return CertMagicInstance.GetCertificate(hello)
	}
	return &DefaultTLSConfig.Certificates[0], nil
}

func genCertificate() (cert tls.Certificate, err error) {
	rawCert, rawKey, err := generateKeyPair()
	if err != nil {
		return
	}
	cert, err = tls.X509KeyPair(rawCert, rawKey)
	return cert, err
}

func generateKeyPair() (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 1
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"STAGENT"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	DefaultTLSConfigCertBytes = rawCert
	DefaultTLSConfigKeyBytes = rawKey

	if CertFileName != "" {
		certOut, err := os.Create(CertFileName)
		if err != nil {
			// todo fix logger
			zap.S().Fatalf("failed to open cert.pem for writing: %s", err)
		}
		if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
			zap.S().Info("failed to pem encode:", err)
		}
		if err := certOut.Close(); err != nil {
			zap.S().Error("error closing cert.pem:", err)
			return nil, nil, err
		}
		zap.S().Infof("write cert to %s", CertFileName)
	}
	if KeyFileName != "" {
		keyOut, err := os.OpenFile(KeyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			zap.S().Info("failed to open key.pem for writing:", err)
		}
		if err = pem.Encode(keyOut, mustPemBlockForKey(priv)); err != nil {
			zap.S().Info("failed to pem encode:", err)
		}
		if err := keyOut.Close(); err != nil {
			zap.S().Error("error closing key.pem:", err)
			return nil, nil, err
		}
		zap.S().Infof("write key to %s", KeyFileName)
	}
	return
}

func mustPemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			zap.S().Errorf("Unable to marshal ECDSA private key: %v", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}
