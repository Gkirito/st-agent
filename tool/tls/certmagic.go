package tls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/gandi"
	"github.com/libdns/godaddy"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

// CertMagicConfig is the configuration for Let's Encrypt / ZeroSSL automatic
// certificate management via certmagic.
type CertMagicConfig struct {
	Domains []string `json:"domains"` // required; at least one domain
	Email   string   `json:"email"`   // contact email for the ACME account

	// CA to use. Supported: "letsencrypt" (default), "zerossl".
	CA string `json:"ca"`

	// KeyType for the certificate private key.
	// Supported: "rsa2048", "rsa4096", "ecdsa" (default), "ed25519".
	KeyType string `json:"key_type"`

	// Dir is the storage directory for certmagic assets. Default: "./certmagic-data".
	Dir string `json:"dir"`

	// Challenge selects the ACME challenge type. Supported: "http" (default), "tls", "dns".
	Challenge string `json:"challenge"`

	// DNS configures the DNS provider for dns-01 challenges (required when challenge="dns").
	DNS *CertMagicDNSConfig `json:"dns"`

	// Alternate ports for HTTP-01 / TLS-ALPN challenges.
	HTTPPort    int `json:"http_port"`
	TLSALPNPort int `json:"tls_alpn_port"`

	// Fallback: if true and ACME fails, log a warning and continue with self-signed.
	// Default: false (startup fails on ACME error).
	Fallback bool `json:"fallback"`

	// ZeroSSL External Account Binding credentials. If empty and using ZeroSSL
	// with an Email, they will be auto-generated.
	EABKeyID  string `json:"eab_key_id"`
	EABMACKey string `json:"eab_mac_key"`
}

// CertMagicDNSConfig configures a DNS provider for the dns-01 challenge.
type CertMagicDNSConfig struct {
	Name   string            `json:"name"`   // provider name: cloudflare, duckdns, gandi, godaddy
	Config map[string]string `json:"config"` // provider-specific key/value pairs
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

// CertMagicInstance is the global certmagic managed config.
// When nil, ACME certificates are not in use.
var CertMagicInstance *certmagic.Config

// managedDomains stores the domain list registered via SetManagedDomains,
// used by GetCertificatePEM to locate cert/key assets in storage.
var managedDomains []string

// ACMETLS1Protocol is the ALPN protocol identifier required for the ACME
// TLS-ALPN-01 challenge. Servers using challenge="tls" must include this
// in their tls.Config.NextProtos.
const ACMETLS1Protocol = "acme-tls/1"

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

// InitCertMagic initialises the global certmagic instance.
//
// After a successful call CertMagicInstance is set and GetCertificate /
// GetCertificatePEM work correctly.
//
// If cfg.Fallback is true and ACME fails, the function logs a warning and
// returns nil — the caller should fall back to self-signed certificates.
func InitCertMagic(ctx context.Context, cfg *CertMagicConfig, log *zap.Logger) error {
	if len(cfg.Domains) == 0 {
		return errors.New("certmagic: no domains configured")
	}

	// ----- certmagic base Config -------------------------------------------
	storageDir := cfg.Dir
	if storageDir == "" {
		storageDir = "./certmagic-data"
	}

	baseCfg := &certmagic.Config{
		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
		KeySource:          certmagic.DefaultKeyGenerator,
		Storage:            &certmagic.FileStorage{Path: storageDir},
		Logger:             log,
	}

	switch strings.ToLower(cfg.KeyType) {
	case "", "ecdsa":
		baseCfg.KeySource = certmagic.StandardKeyGenerator{KeyType: certmagic.P256}
	case "ecdsa-p384":
		baseCfg.KeySource = certmagic.StandardKeyGenerator{KeyType: certmagic.P384}
	case "rsa2048":
		baseCfg.KeySource = certmagic.StandardKeyGenerator{KeyType: certmagic.RSA2048}
	case "rsa4096":
		baseCfg.KeySource = certmagic.StandardKeyGenerator{KeyType: certmagic.RSA4096}
	case "ed25519":
		baseCfg.KeySource = certmagic.StandardKeyGenerator{KeyType: certmagic.ED25519}
	default:
		return fmt.Errorf("certmagic: unsupported key_type: %s", cfg.KeyType)
	}

	// ----- Cache & managed config (created before issuer for GetConfigForCert) ---
	var magicCfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magicCfg, nil
		},
		Logger: log,
	})
	magicCfg = certmagic.New(cache, *baseCfg)

	// ----- ACME Issuer (properly initialised via NewACMEIssuer) ------------
	issuerTemplate := certmagic.ACMEIssuer{
		Email:  cfg.Email,
		Agreed: true,
		Logger: log,
	}

	switch strings.ToLower(cfg.CA) {
	case "", "letsencrypt", "le":
		issuerTemplate.CA = certmagic.LetsEncryptProductionCA
	case "zerossl", "zero":
		issuerTemplate.CA = certmagic.ZeroSSLProductionCA
		switch {
		case cfg.EABKeyID != "" && cfg.EABMACKey != "":
			issuerTemplate.ExternalAccount = &acme.EAB{
				KeyID:  cfg.EABKeyID,
				MACKey: cfg.EABMACKey,
			}
		case cfg.Email != "":
			eab, err := genZeroSSLEAB(cfg.Email)
			if err != nil {
				return fmt.Errorf("certmagic: failed to auto-generate ZeroSSL EAB: %w", err)
			}
			issuerTemplate.ExternalAccount = eab
		default:
			return errors.New("certmagic: ZeroSSL requires EAB credentials or an email to auto-generate them")
		}
	default:
		return fmt.Errorf("certmagic: unsupported CA: %s", cfg.CA)
	}

	// ----- Challenge setup -------------------------------------------------
	switch strings.ToLower(cfg.Challenge) {
	case "", "http":
		issuerTemplate.DisableHTTPChallenge = false
		issuerTemplate.DisableTLSALPNChallenge = true
		if cfg.HTTPPort > 0 {
			issuerTemplate.AltHTTPPort = cfg.HTTPPort
		}
	case "tls":
		issuerTemplate.DisableHTTPChallenge = true
		issuerTemplate.DisableTLSALPNChallenge = false
		if cfg.TLSALPNPort > 0 {
			issuerTemplate.AltTLSALPNPort = cfg.TLSALPNPort
		}
	case "dns":
		issuerTemplate.DisableHTTPChallenge = true
		issuerTemplate.DisableTLSALPNChallenge = true
		if cfg.DNS == nil {
			return errors.New("certmagic: dns challenge requires a DNS provider config")
		}
		solver, err := buildDNS01Solver(cfg.DNS)
		if err != nil {
			return fmt.Errorf("certmagic: %w", err)
		}
		issuerTemplate.DNS01Solver = solver
	default:
		return fmt.Errorf("certmagic: unsupported challenge type: %s", cfg.Challenge)
	}

	issuer := certmagic.NewACMEIssuer(magicCfg, issuerTemplate)
	magicCfg.Issuers = []certmagic.Issuer{issuer}

	// ----- Obtain certificates ---------------------------------------------
	manageCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := magicCfg.ManageSync(manageCtx, cfg.Domains); err != nil {
		if cfg.Fallback {
			log.Warn("certmagic: ACME failed, falling back to self-signed", zap.Error(err))
			return nil
		}
		return fmt.Errorf("certmagic: failed to obtain certificates: %w", err)
	}

	CertMagicInstance = magicCfg
	managedDomains = cfg.Domains

	log.Info("certmagic: ACME certificates obtained",
		zap.Strings("domains", cfg.Domains),
		zap.String("ca", issuerTemplate.CA),
	)
	return nil
}

// ---------------------------------------------------------------------------
// DNS provider construction
// ---------------------------------------------------------------------------

// SupportedDNSProviders returns a list of supported DNS provider names.
func SupportedDNSProviders() []string {
	return []string{"cloudflare", "duckdns", "gandi", "godaddy"}
}

func buildDNS01Solver(dns *CertMagicDNSConfig) (*certmagic.DNS01Solver, error) {
	prov, err := buildDNSProvider(dns)
	if err != nil {
		return nil, err
	}
	return &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: prov,
		},
	}, nil
}

func buildDNSProvider(dns *CertMagicDNSConfig) (certmagic.DNSProvider, error) {
	switch strings.ToLower(dns.Name) {
	case "cloudflare":
		token, ok := dns.Config["api_token"]
		if !ok || token == "" {
			return nil, errors.New("cloudflare: missing api_token in dns config")
		}
		return &cloudflare.Provider{APIToken: token}, nil

	case "duckdns":
		token, ok := dns.Config["api_token"]
		if !ok || token == "" {
			return nil, errors.New("duckdns: missing api_token in dns config")
		}
		p := &duckdns.Provider{APIToken: token}
		if override, ok := dns.Config["override_domain"]; ok {
			p.OverrideDomain = override
		}
		return p, nil

	case "gandi":
		token, ok := dns.Config["api_token"]
		if !ok || token == "" {
			return nil, errors.New("gandi: missing api_token in dns config")
		}
		return &gandi.Provider{BearerToken: token}, nil

	case "godaddy":
		token, ok := dns.Config["api_token"]
		if !ok || token == "" {
			return nil, errors.New("godaddy: missing api_token in dns config")
		}
		return &godaddy.Provider{APIToken: token}, nil

	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", dns.Name)
	}
}

// ---------------------------------------------------------------------------
// ZeroSSL EAB helper
// ---------------------------------------------------------------------------

func genZeroSSLEAB(email string) (*acme.EAB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost,
		"https://api.zerossl.com/acme/eab-credentials-email",
		strings.NewReader(url.Values{"email": []string{email}}.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ZeroSSL EAB request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", certmagic.UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send ZeroSSL EAB request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed decoding ZeroSSL EAB API response: %w", err)
	}
	if result.Error.Code != 0 {
		return nil, fmt.Errorf("failed getting ZeroSSL EAB credentials: HTTP %d: %s (code %d)",
			resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}
	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, nil
}

// ---------------------------------------------------------------------------
// Certificate retrieval
// ---------------------------------------------------------------------------

// GetCertificatePEM returns the PEM-encoded certificate and private key
// for the first managed domain from certmagic storage.
//
// When CertMagicInstance is nil the function falls back to the self-signed
// defaults (DefaultTLSConfigCertBytes / DefaultTLSConfigKeyBytes).
func GetCertificatePEM(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	if CertMagicInstance == nil {
		return DefaultTLSConfigCertBytes, DefaultTLSConfigKeyBytes, nil
	}
	if len(managedDomains) == 0 {
		return nil, nil, errors.New("certmagic: no managed domains registered")
	}
	if len(CertMagicInstance.Issuers) == 0 {
		return nil, nil, errors.New("certmagic: no issuers configured")
	}

	issuerKey := CertMagicInstance.Issuers[0].IssuerKey()
	domain := managedDomains[0]

	var keys certmagic.KeyBuilder
	certPath := keys.SiteCert(issuerKey, domain)
	keyPath := keys.SitePrivateKey(issuerKey, domain)

	certPEM, err = CertMagicInstance.Storage.Load(ctx, certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("certmagic: failed to load cert for %q: %w", domain, err)
	}
	keyPEM, err = CertMagicInstance.Storage.Load(ctx, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("certmagic: failed to load key for %q: %w", domain, err)
	}
	return certPEM, keyPEM, nil
}
