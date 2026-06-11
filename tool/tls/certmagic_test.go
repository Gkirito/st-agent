package tls

import (
	"context"
	"testing"

	"github.com/caddyserver/certmagic"
)

func TestBuildDNSProvider_Cloudflare(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name:   "cloudflare",
		Config: map[string]string{"api_token": "test-token"},
	}
	_, err := buildDNSProvider(dns)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestBuildDNSProvider_CloudflareMissingToken(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name:   "cloudflare",
		Config: map[string]string{},
	}
	_, err := buildDNSProvider(dns)
	if err == nil {
		t.Fatal("expected error for missing api_token, got nil")
	}
}

func TestBuildDNSProvider_DuckDNS(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name:   "duckdns",
		Config: map[string]string{"api_token": "test-token"},
	}
	_, err := buildDNSProvider(dns)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestBuildDNSProvider_DuckDNSWithOverride(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name: "duckdns",
		Config: map[string]string{
			"api_token":       "test-token",
			"override_domain": "override.example.com",
		},
	}
	_, err := buildDNSProvider(dns)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestBuildDNSProvider_Gandi(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name:   "gandi",
		Config: map[string]string{"api_token": "test-token"},
	}
	_, err := buildDNSProvider(dns)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestBuildDNSProvider_GoDaddy(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name:   "godaddy",
		Config: map[string]string{"api_token": "test-token"},
	}
	_, err := buildDNSProvider(dns)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestBuildDNSProvider_Unsupported(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name: "unsupported",
	}
	_, err := buildDNSProvider(dns)
	if err == nil {
		t.Fatal("expected error for unsupported provider, got nil")
	}
}

func TestBuildDNS01Solver(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name:   "cloudflare",
		Config: map[string]string{"api_token": "test-token"},
	}
	solver, err := buildDNS01Solver(dns)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if solver == nil {
		t.Fatal("expected non-nil solver")
	}
}

func TestBuildDNS01Solver_InvalidProvider(t *testing.T) {
	dns := &CertMagicDNSConfig{
		Name: "invalid",
	}
	_, err := buildDNS01Solver(dns)
	if err == nil {
		t.Fatal("expected error for invalid provider, got nil")
	}
}

func TestCertMagicConfigDefaults(t *testing.T) {
	cfg := &CertMagicConfig{
		Domains: []string{"example.com"},
		Email:   "user@example.com",
	}

	// Zero-value fields should default correctly at init time
	if cfg.CA != "" {
		t.Errorf("default CA should be empty, got %q", cfg.CA)
	}
	if cfg.KeyType != "" {
		t.Errorf("default KeyType should be empty, got %q", cfg.KeyType)
	}
	if cfg.Challenge != "" {
		t.Errorf("default Challenge should be empty, got %q", cfg.Challenge)
	}
}

func TestSupportedDNSProviders(t *testing.T) {
	providers := SupportedDNSProviders()
	if len(providers) != 4 {
		t.Fatalf("expected 4 providers, got %d: %v", len(providers), providers)
	}
	expected := map[string]bool{
		"cloudflare": true,
		"duckdns":    true,
		"gandi":      true,
		"godaddy":    true,
	}
	for _, p := range providers {
		if !expected[p] {
			t.Errorf("unexpected provider: %s", p)
		}
	}
}

func TestInitCertMagic_EmptyDomains(t *testing.T) {
	cfg := &CertMagicConfig{}
	err := InitCertMagic(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for empty domains, got nil")
	}
}

func TestInitCertMagic_InvalidCA(t *testing.T) {
	cfg := &CertMagicConfig{
		Domains: []string{"example.com"},
		Email:   "user@example.com",
		CA:      "bogus-ca",
	}
	err := InitCertMagic(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid CA, got nil")
	}
}

func TestInitCertMagic_InvalidKeyType(t *testing.T) {
	cfg := &CertMagicConfig{
		Domains:  []string{"example.com"},
		Email:    "user@example.com",
		KeyType:  "bogus-key",
	}
	err := InitCertMagic(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid key type, got nil")
	}
}

func TestInitCertMagic_InvalidChallenge(t *testing.T) {
	cfg := &CertMagicConfig{
		Domains:   []string{"example.com"},
		Email:     "user@example.com",
		Challenge: "bogus-challenge",
	}
	err := InitCertMagic(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid challenge, got nil")
	}
}

func TestInitCertMagic_DNSChallengeNoProvider(t *testing.T) {
	cfg := &CertMagicConfig{
		Domains:   []string{"example.com"},
		Email:     "user@example.com",
		Challenge: "dns",
	}
	err := InitCertMagic(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for DNS challenge without provider, got nil")
	}
}

func TestGetCertificatePEM_NilInstance(t *testing.T) {
	CertMagicInstance = nil
	DefaultTLSConfigCertBytes = []byte("test-cert")
	DefaultTLSConfigKeyBytes = []byte("test-key")

	certPEM, keyPEM, err := GetCertificatePEM(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if string(certPEM) != "test-cert" {
		t.Errorf("expected test-cert, got %s", certPEM)
	}
	if string(keyPEM) != "test-key" {
		t.Errorf("expected test-key, got %s", keyPEM)
	}
}

func TestGetCertificatePEM_NoManagedDomains(t *testing.T) {
	CertMagicInstance = &certmagic.Config{}
	managedDomains = nil

	_, _, err := GetCertificatePEM(context.Background())
	if err == nil {
		t.Fatal("expected error for no managed domains, got nil")
	}

	CertMagicInstance = nil
	managedDomains = nil
}

func TestGetCertificatePEM_NoIssuers(t *testing.T) {
	CertMagicInstance = &certmagic.Config{}
	managedDomains = []string{"example.com"}

	_, _, err := GetCertificatePEM(context.Background())
	if err == nil {
		t.Fatal("expected error for no issuers, got nil")
	}

	CertMagicInstance = nil
	managedDomains = nil
}
