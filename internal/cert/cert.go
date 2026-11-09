// Package cert creates and loads the self-signed certificate used by the
// agent tunnel. The public HTTP listener does not use this certificate.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadOrGenerate loads certFile/keyFile or creates a self-signed pair.
// It returns the certificate and its SHA-256 fingerprint in "sha256:<hex>" form.
func LoadOrGenerate(certFile, keyFile string, autoGenerate bool, publicHost string) (tls.Certificate, string, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, "", fmt.Errorf("cert_file and key_file are required")
	}
	certOK, err := exists(certFile)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyOK, err := exists(keyFile)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if certOK != keyOK {
		return tls.Certificate{}, "", fmt.Errorf("cert_file and key_file must both exist or both be absent")
	}
	if certOK {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("load tunnel certificate: %w", err)
		}
		if len(c.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
				c.Leaf = leaf
			}
		}
		return c, Fingerprint(c), nil
	}
	if !autoGenerate {
		return tls.Certificate{}, "", fmt.Errorf("tunnel certificate not found and auto_generate is false")
	}
	c, err := generate(publicHost)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Certificate[0],
	}), 0o644); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("write certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(c.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("marshal private key: %w", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}), 0o600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("write private key: %w", err)
	}
	return c, Fingerprint(c), nil
}

func generate(publicHost string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cproxy tunnel", Organization: []string{"cproxy"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if h := strings.TrimSpace(publicHost); h != "" {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// Fingerprint returns "sha256:<hex>" for the leaf certificate.
func Fingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FingerprintFile returns the SHA-256 pin of the first certificate in a PEM file.
func FingerprintFile(path string) (string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s does not contain a PEM certificate", path)
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ParseFingerprint accepts "sha256:<hex>" or a bare hex SHA-256 digest.
func ParseFingerprint(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "sha256:")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate fingerprint: %w", err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("certificate fingerprint must be 32 bytes, got %d", len(b))
	}
	return b, nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
