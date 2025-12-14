package hysteria

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gkirito/st-agent/tunnel/hysteria/utils"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/auth"
	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/hysteria/extras/v2/masq"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/outbounds"
	"github.com/apernet/hysteria/extras/v2/sniff"
	"github.com/apernet/hysteria/extras/v2/trafficlogger"
	eUtils "github.com/apernet/hysteria/extras/v2/utils"
)

const (
	defaultListenAddr = ":443"
)

type configError struct {
	Field string
	Err   error
}

func (e configError) Error() string {
	return fmt.Sprintf("invalid config: %s: %s", e.Field, e.Err)
}

func (e configError) Unwrap() error {
	return e.Err
}

type ServerConfig struct {
	Listen                string                      `json:"listen"`
	Obfs                  serverConfigObfs            `json:"obfs"`
	TLS                   *serverConfigTLS            `json:"tls"`
	ACME                  *serverConfigACME           `json:"acme"`
	QUIC                  serverConfigQUIC            `json:"quic"`
	Bandwidth             serverConfigBandwidth       `json:"bandwidth"`
	IgnoreClientBandwidth bool                        `json:"ignoreClientBandwidth"`
	SpeedTest             bool                        `json:"speedTest"`
	DisableUDP            bool                        `json:"disableUDP"`
	UDPIdleTimeout        time.Duration               `json:"udpIdleTimeout"`
	Auth                  serverConfigAuth            `json:"auth"`
	Resolver              serverConfigResolver        `json:"resolver"`
	Sniff                 serverConfigSniff           `json:"sniff"`
	ACL                   serverConfigACL             `json:"acl"`
	Outbounds             []serverConfigOutboundEntry `json:"outbounds"`
	TrafficStats          serverConfigTrafficStats    `json:"trafficStats"`
	Masquerade            serverConfigMasquerade      `json:"masquerade"`
	logger                *zap.Logger                 `json:"-"`
}

func (c *ServerConfig) WithLogger(l *zap.Logger) *ServerConfig {
	c.logger = l
	return c
}

func (c *ServerConfig) loggerOrDefault() *zap.Logger {
	if c.logger != nil {
		return c.logger
	}
	return zap.L().Named("hysteria")
}

type serverConfigObfsSalamander struct {
	Password string `json:"password"`
}

type serverConfigObfs struct {
	Type       string                     `json:"type"`
	Salamander serverConfigObfsSalamander `json:"salamander"`
}

type serverConfigTLS struct {
	Cert     string           `json:"cert"`
	Key      string           `json:"key"`
	SNIGuard string           `json:"sniGuard"` // "disable", "dns-san", "strict"
	ClientCA string           `json:"clientCA"`
	SelfTls  *tls.Certificate `json:"-"`
}

type serverConfigACME struct {
	// Common fields
	Domains    []string `json:"domains"`
	Email      string   `json:"email"`
	CA         string   `json:"ca"`
	ListenHost string   `json:"listenHost"`
	Dir        string   `json:"dir"`

	// Type selection
	Type string               `json:"type"`
	HTTP serverConfigACMEHTTP `json:"http"`
	TLS  serverConfigACMETLS  `json:"tls"`
	DNS  serverConfigACMEDNS  `json:"dns"`

	// Legacy fields for backwards compatibility
	// Only applicable when Type is empty
	DisableHTTP    bool `json:"disableHTTP"`
	DisableTLSALPN bool `json:"disableTLSALPN"`
	AltHTTPPort    int  `json:"altHTTPPort"`
	AltTLSALPNPort int  `json:"altTLSALPNPort"`
}

type serverConfigACMEHTTP struct {
	AltPort int `json:"altPort"`
}

type serverConfigACMETLS struct {
	AltPort int `json:"altPort"`
}

type serverConfigACMEDNS struct {
	Name   string            `json:"name"`
	Config map[string]string `json:"config"`
}

type serverConfigQUIC struct {
	InitStreamReceiveWindow     uint64        `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64        `json:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64        `json:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64        `json:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration `json:"maxIdleTimeout"`
	MaxIncomingStreams          int64         `json:"maxIncomingStreams"`
	DisablePathMTUDiscovery     bool          `json:"disablePathMTUDiscovery"`
}

type serverConfigBandwidth struct {
	Up   string `json:"up"`
	Down string `json:"down"`
}

type serverConfigAuthHTTP struct {
	URL      string `json:"url"`
	Insecure bool   `json:"insecure"`
}

type serverConfigAuth struct {
	Type     string               `json:"type"`
	Password string               `json:"password"`
	UserPass map[string]string    `json:"userpass"`
	HTTP     serverConfigAuthHTTP `json:"http"`
	Command  string               `json:"command"`
}

type serverConfigResolverTCP struct {
	Addr    string        `json:"addr"`
	Timeout time.Duration `json:"timeout"`
}

type serverConfigResolverUDP struct {
	Addr    string        `json:"addr"`
	Timeout time.Duration `json:"timeout"`
}

type serverConfigResolverTLS struct {
	Addr     string        `json:"addr"`
	Timeout  time.Duration `json:"timeout"`
	SNI      string        `json:"sni"`
	Insecure bool          `json:"insecure"`
}

type serverConfigResolverHTTPS struct {
	Addr     string        `json:"addr"`
	Timeout  time.Duration `json:"timeout"`
	SNI      string        `json:"sni"`
	Insecure bool          `json:"insecure"`
}

type serverConfigResolver struct {
	Type  string                    `json:"type"`
	TCP   serverConfigResolverTCP   `json:"tcp"`
	UDP   serverConfigResolverUDP   `json:"udp"`
	TLS   serverConfigResolverTLS   `json:"tls"`
	HTTPS serverConfigResolverHTTPS `json:"https"`
}

type serverConfigSniff struct {
	Enable        bool          `json:"enable"`
	Timeout       time.Duration `json:"timeout"`
	RewriteDomain bool          `json:"rewriteDomain"`
	TCPPorts      string        `json:"tcpPorts"`
	UDPPorts      string        `json:"udpPorts"`
}

type serverConfigACL struct {
	File              string        `json:"file"`
	Inline            []string      `json:"inline"`
	GeoIP             string        `json:"geoip"`
	GeoSite           string        `json:"geosite"`
	GeoUpdateInterval time.Duration `json:"geoUpdateInterval"`
}

type serverConfigOutboundDirect struct {
	Mode       string `json:"mode"`
	BindIPv4   string `json:"bindIPv4"`
	BindIPv6   string `json:"bindIPv6"`
	BindDevice string `json:"bindDevice"`
	FastOpen   bool   `json:"fastOpen"`
}

type serverConfigOutboundSOCKS5 struct {
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type serverConfigOutboundHTTP struct {
	URL      string `json:"url"`
	Insecure bool   `json:"insecure"`
}

type serverConfigOutboundEntry struct {
	Name   string                     `json:"name"`
	Type   string                     `json:"type"`
	Direct serverConfigOutboundDirect `json:"direct"`
	SOCKS5 serverConfigOutboundSOCKS5 `json:"socks5"`
	HTTP   serverConfigOutboundHTTP   `json:"http"`
}

type serverConfigTrafficStats struct {
	Listen string `json:"listen"`
	Secret string `json:"secret"`
}

type serverConfigMasqueradeFile struct {
	Dir string `json:"dir"`
}

type serverConfigMasqueradeProxy struct {
	URL         string `json:"url"`
	RewriteHost bool   `json:"rewriteHost"`
	Insecure    bool   `json:"insecure"`
}

type serverConfigMasqueradeString struct {
	Content    string            `json:"content"`
	Headers    map[string]string `json:"headers"`
	StatusCode int               `json:"statusCode"`
}

type serverConfigMasquerade struct {
	Type        string                       `json:"type"`
	File        serverConfigMasqueradeFile   `json:"file"`
	Proxy       serverConfigMasqueradeProxy  `json:"proxy"`
	String      serverConfigMasqueradeString `json:"string"`
	ListenHTTP  string                       `json:"listenHTTP"`
	ListenHTTPS string                       `json:"listenHTTPS"`
	ForceHTTPS  bool                         `json:"forceHTTPS"`
}

func (c *ServerConfig) fillConn(hyConfig *server.Config) error {
	listenAddr := c.Listen
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}
	uAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	conn, err := correctnet.ListenUDP("udp", uAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		hyConfig.Conn = conn
		return nil
	case "salamander":
		ob, err := obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return configError{Field: "obfs.salamander.password", Err: err}
		}
		hyConfig.Conn = obfs.WrapPacketConn(conn, ob)
		return nil
	default:
		return configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
}

func (c *ServerConfig) fillTLSConfig(hyConfig *server.Config) error {
	// log := c.loggerOrDefault()
	if c.TLS == nil && c.ACME == nil {
		return configError{Field: "tls", Err: errors.New("must set either tls or acme")}
	}
	if c.TLS != nil && c.ACME != nil {
		return configError{Field: "tls", Err: errors.New("cannot set both tls and acme")}
	}
	if c.TLS != nil {
		// SNI guard
		var sniGuard utils.SNIGuardFunc
		switch strings.ToLower(c.TLS.SNIGuard) {
		case "", "dns-san":
			sniGuard = utils.SNIGuardDNSSAN
		case "strict":
			sniGuard = utils.SNIGuardStrict
		case "disable":
			sniGuard = nil
		default:
			return configError{Field: "tls.sniGuard", Err: errors.New("unsupported SNI guard")}
		}
		// Local TLS cert
		if c.TLS.Cert != "" && c.TLS.Key != "" {
			certLoader := &utils.LocalCertificateLoader{
				CertFile: c.TLS.Cert,
				KeyFile:  c.TLS.Key,
				SNIGuard: sniGuard,
			}
			// Try loading the cert-key pair here to catch errors early
			// (e.g. invalid files or insufficient permissions)
			err := certLoader.InitializeCache()
			if err != nil {
				var pathErr *os.PathError
				if errors.As(err, &pathErr) {
					if pathErr.Path == c.TLS.Cert {
						return configError{Field: "tls.cert", Err: pathErr}
					}
					if pathErr.Path == c.TLS.Key {
						return configError{Field: "tls.key", Err: pathErr}
					}
				}
				return configError{Field: "tls", Err: err}
			}
			// Use GetCertificate instead of Certificates so that
			// users can update the cert without restarting the server.
			hyConfig.TLSConfig.GetCertificate = certLoader.GetCertificate
		} else if c.TLS.SelfTls != nil {
			hyConfig.TLSConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return c.TLS.SelfTls, nil
			}
		} else {
			return configError{Field: "tls", Err: errors.New("empty cert or key path")}
		}

		// Client CA
		if c.TLS.ClientCA != "" {
			ca, err := os.ReadFile(c.TLS.ClientCA)
			if err != nil {
				return configError{Field: "tls.clientCA", Err: err}
			}
			cPool := x509.NewCertPool()
			if !cPool.AppendCertsFromPEM(ca) {
				return configError{Field: "tls.clientCA", Err: errors.New("failed to parse client CA certificate")}
			}
			hyConfig.TLSConfig.ClientCAs = cPool
		}
	}
	//  else {
	// 	// ACME
	// 	dataDir := c.ACME.Dir
	// 	cmCfg := &certmagic.Config{
	// 		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
	// 		KeySource:          certmagic.DefaultKeyGenerator,
	// 		Storage:            &certmagic.FileStorage{Path: dataDir},
	// 		Logger:             log,
	// 	}
	// 	cmIssuer := certmagic.NewACMEIssuer(cmCfg, certmagic.ACMEIssuer{
	// 		Email:      c.ACME.Email,
	// 		Agreed:     true,
	// 		ListenHost: c.ACME.ListenHost,
	// 		Logger:     log,
	// 	})
	// 	switch strings.ToLower(c.ACME.CA) {
	// 	case "letsencrypt", "le", "":
	// 		// Default to Let's Encrypt
	// 		cmIssuer.CA = certmagic.LetsEncryptProductionCA
	// 	case "zerossl", "zero":
	// 		cmIssuer.CA = certmagic.ZeroSSLProductionCA
	// 		eab, err := genZeroSSLEAB(c.ACME.Email)
	// 		if err != nil {
	// 			return configError{Field: "acme.ca", Err: err}
	// 		}
	// 		cmIssuer.ExternalAccount = eab
	// 	default:
	// 		return configError{Field: "acme.ca", Err: errors.New("unsupported CA")}
	// 	}

	// 	switch strings.ToLower(c.ACME.Type) {
	// 	case "http":
	// 		cmIssuer.DisableHTTPChallenge = false
	// 		cmIssuer.DisableTLSALPNChallenge = true
	// 		cmIssuer.DNS01Solver = nil
	// 		cmIssuer.AltHTTPPort = c.ACME.HTTP.AltPort
	// 	case "tls":
	// 		cmIssuer.DisableHTTPChallenge = true
	// 		cmIssuer.DisableTLSALPNChallenge = false
	// 		cmIssuer.DNS01Solver = nil
	// 		cmIssuer.AltTLSALPNPort = c.ACME.TLS.AltPort
	// 	case "dns":
	// 		cmIssuer.DisableHTTPChallenge = true
	// 		cmIssuer.DisableTLSALPNChallenge = true
	// 		if c.ACME.DNS.Name == "" {
	// 			return configError{Field: "acme.dns.name", Err: errors.New("empty DNS provider name")}
	// 		}
	// 		if c.ACME.DNS.Config == nil {
	// 			return configError{Field: "acme.dns.config", Err: errors.New("empty DNS provider config")}
	// 		}
	// 		switch strings.ToLower(c.ACME.DNS.Name) {
	// 		case "cloudflare":
	// 			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
	// 				DNSProvider: &cloudflare.Provider{
	// 					APIToken: c.ACME.DNS.Config["cloudflare_api_token"],
	// 				},
	// 			}
	// 		case "duckdns":
	// 			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
	// 				DNSProvider: &duckdns.Provider{
	// 					APIToken:       c.ACME.DNS.Config["duckdns_api_token"],
	// 					OverrideDomain: c.ACME.DNS.Config["duckdns_override_domain"],
	// 				},
	// 			}
	// 		case "gandi":
	// 			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
	// 				DNSProvider: &gandi.Provider{
	// 					BearerToken: c.ACME.DNS.Config["gandi_api_token"],
	// 				},
	// 			}
	// 		case "godaddy":
	// 			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
	// 				DNSProvider: &godaddy.Provider{
	// 					APIToken: c.ACME.DNS.Config["godaddy_api_token"],
	// 				},
	// 			}
	// 		case "namedotcom":
	// 			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
	// 				DNSProvider: &namedotcom.Provider{
	// 					Token:  c.ACME.DNS.Config["namedotcom_token"],
	// 					User:   c.ACME.DNS.Config["namedotcom_user"],
	// 					Server: c.ACME.DNS.Config["namedotcom_server"],
	// 				},
	// 			}
	// 		case "vultr":
	// 			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
	// 				DNSProvider: &vultr.Provider{
	// 					APIToken: c.ACME.DNS.Config["vultr_api_token"],
	// 				},
	// 			}
	// 		default:
	// 			return configError{Field: "acme.dns.name", Err: errors.New("unsupported DNS provider")}
	// 		}
	// 	case "":
	// 		// Legacy compatibility mode
	// 		cmIssuer.DisableHTTPChallenge = c.ACME.DisableHTTP
	// 		cmIssuer.DisableTLSALPNChallenge = c.ACME.DisableTLSALPN
	// 		cmIssuer.AltHTTPPort = c.ACME.AltHTTPPort
	// 		cmIssuer.AltTLSALPNPort = c.ACME.AltTLSALPNPort
	// 	default:
	// 		return configError{Field: "acme.type", Err: errors.New("unsupported ACME type")}
	// 	}

	// 	cmCfg.Issuers = []certmagic.Issuer{cmIssuer}
	// 	cmCache := certmagic.NewCache(certmagic.CacheOptions{
	// 		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
	// 			return cmCfg, nil
	// 		},
	// 		Logger: log,
	// 	})
	// 	cmCfg = certmagic.New(cmCache, *cmCfg)

	// 	if len(c.ACME.Domains) == 0 {
	// 		return configError{Field: "acme.domains", Err: errors.New("empty domains")}
	// 	}
	// 	err := cmCfg.ManageSync(context.Background(), c.ACME.Domains)
	// 	if err != nil {
	// 		return configError{Field: "acme.domains", Err: err}
	// 	}
	// 	hyConfig.TLSConfig.GetCertificate = cmCfg.GetCertificate
	// }
	return nil
}

// func genZeroSSLEAB(email string) (*acme.EAB, error) {
// 	req, err := http.NewRequest(
// 		http.MethodPost,
// 		"https://api.zerossl.com/acme/eab-credentials-email",
// 		strings.NewReader(url.Values{"email": []string{email}}.Encode()),
// 	)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to creare ZeroSSL EAB request: %w", err)
// 	}
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
// 	req.Header.Set("User-Agent", certmagic.UserAgent)
// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to send ZeroSSL EAB request: %w", err)
// 	}
// 	defer func() { _ = resp.Body.Close() }()

// 	var result struct {
// 		Success bool `json:"success"`
// 		Error   struct {
// 			Code int    `json:"code"`
// 			Type string `json:"type"`
// 		} `json:"error"`
// 		EABKID     string `json:"eab_kid"`
// 		EABHMACKey string `json:"eab_hmac_key"`
// 	}
// 	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
// 		return nil, fmt.Errorf("failed decoding ZeroSSL EAB API response: %w", err)
// 	}
// 	if result.Error.Code != 0 {
// 		return nil, fmt.Errorf("failed getting ZeroSSL EAB credentials: HTTP %d: %s (code %d)", resp.StatusCode, result.Error.Type, result.Error.Code)
// 	}
// 	if resp.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
// 	}

// 	return &acme.EAB{
// 		KeyID:  result.EABKID,
// 		MACKey: result.EABHMACKey,
// 	}, nil
// }

func (c *ServerConfig) fillQUICConfig(hyConfig *server.Config) error {
	hyConfig.QUICConfig = server.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             c.QUIC.MaxIncomingStreams,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func serverConfigOutboundDirectToOutbound(c serverConfigOutboundDirect) (outbounds.PluggableOutbound, error) {
	opts := outbounds.DirectOutboundOptions{}
	switch strings.ToLower(c.Mode) {
	case "", "auto":
		opts.Mode = outbounds.DirectOutboundModeAuto
	case "64":
		opts.Mode = outbounds.DirectOutboundMode64
	case "46":
		opts.Mode = outbounds.DirectOutboundMode46
	case "6":
		opts.Mode = outbounds.DirectOutboundMode6
	case "4":
		opts.Mode = outbounds.DirectOutboundMode4
	default:
		return nil, configError{Field: "outbounds.direct.mode", Err: errors.New("unsupported mode")}
	}
	bindIP := len(c.BindIPv4) > 0 || len(c.BindIPv6) > 0
	bindDevice := len(c.BindDevice) > 0
	if bindIP && bindDevice {
		return nil, configError{Field: "outbounds.direct", Err: errors.New("cannot bind both IP and device")}
	}
	if bindIP {
		ip4, ip6 := net.ParseIP(c.BindIPv4), net.ParseIP(c.BindIPv6)
		if len(c.BindIPv4) > 0 && ip4 == nil {
			return nil, configError{Field: "outbounds.direct.bindIPv4", Err: errors.New("invalid IPv4 address")}
		}
		if len(c.BindIPv6) > 0 && ip6 == nil {
			return nil, configError{Field: "outbounds.direct.bindIPv6", Err: errors.New("invalid IPv6 address")}
		}
		opts.BindIP4 = ip4
		opts.BindIP6 = ip6
	}
	if bindDevice {
		opts.DeviceName = c.BindDevice
	}
	opts.FastOpen = c.FastOpen
	return outbounds.NewDirectOutboundWithOptions(opts)
}

func serverConfigOutboundSOCKS5ToOutbound(c serverConfigOutboundSOCKS5) (outbounds.PluggableOutbound, error) {
	if c.Addr == "" {
		return nil, configError{Field: "outbounds.socks5.addr", Err: errors.New("empty socks5 address")}
	}
	return outbounds.NewSOCKS5Outbound(c.Addr, c.Username, c.Password), nil
}

func serverConfigOutboundHTTPToOutbound(c serverConfigOutboundHTTP) (outbounds.PluggableOutbound, error) {
	if c.URL == "" {
		return nil, configError{Field: "outbounds.http.url", Err: errors.New("empty http address")}
	}
	return outbounds.NewHTTPOutbound(c.URL, c.Insecure)
}

func (c *ServerConfig) fillRequestHook(hyConfig *server.Config) error {
	if c.Sniff.Enable {
		s := &sniff.Sniffer{
			Timeout:       c.Sniff.Timeout,
			RewriteDomain: c.Sniff.RewriteDomain,
		}
		if c.Sniff.TCPPorts != "" {
			s.TCPPorts = eUtils.ParsePortUnion(c.Sniff.TCPPorts)
			if s.TCPPorts == nil {
				return configError{Field: "sniff.tcpPorts", Err: errors.New("invalid port union")}
			}
		}
		if c.Sniff.UDPPorts != "" {
			s.UDPPorts = eUtils.ParsePortUnion(c.Sniff.UDPPorts)
			if s.UDPPorts == nil {
				return configError{Field: "sniff.udpPorts", Err: errors.New("invalid port union")}
			}
		}
		hyConfig.RequestHook = s
	}
	return nil
}

func (c *ServerConfig) fillOutboundConfig(hyConfig *server.Config) error {
	log := c.loggerOrDefault()
	// Resolver, ACL, actual outbound are all implemented through the Outbound interface.
	// Depending on the config, we build a chain like this:
	// Resolver(ACL(Outbounds...))

	// Outbounds
	var obs []outbounds.OutboundEntry
	if len(c.Outbounds) == 0 {
		// Guarantee we have at least one outbound
		obs = []outbounds.OutboundEntry{{
			Name:     "default",
			Outbound: outbounds.NewDirectOutboundSimple(outbounds.DirectOutboundModeAuto),
		}}
	} else {
		obs = make([]outbounds.OutboundEntry, len(c.Outbounds))
		for i, entry := range c.Outbounds {
			if entry.Name == "" {
				return configError{Field: "outbounds.name", Err: errors.New("empty outbound name")}
			}
			var ob outbounds.PluggableOutbound
			var err error
			switch strings.ToLower(entry.Type) {
			case "direct":
				ob, err = serverConfigOutboundDirectToOutbound(entry.Direct)
			case "socks5":
				ob, err = serverConfigOutboundSOCKS5ToOutbound(entry.SOCKS5)
			case "http":
				ob, err = serverConfigOutboundHTTPToOutbound(entry.HTTP)
			default:
				err = configError{Field: "outbounds.type", Err: errors.New("unsupported outbound type")}
			}
			if err != nil {
				return err
			}
			obs[i] = outbounds.OutboundEntry{Name: entry.Name, Outbound: ob}
		}
	}

	var uOb outbounds.PluggableOutbound // "unified" outbound

	// ACL
	hasACL := false
	if c.ACL.File != "" && len(c.ACL.Inline) > 0 {
		return configError{Field: "acl", Err: errors.New("cannot set both acl.file and acl.inline")}
	}
	gLoader := &utils.GeoLoader{
		GeoIPFilename:   c.ACL.GeoIP,
		GeoSiteFilename: c.ACL.GeoSite,
		UpdateInterval:  c.ACL.GeoUpdateInterval,
		DownloadFunc: func(filename, downloadURL string) {
			log.Info("downloading database", zap.String("filename", filename), zap.String("url", downloadURL))
		},
		DownloadErrFunc: func(err error) {
			if err != nil {
				log.Error("failed to download database", zap.Error(err))
			}
		},
	}
	if c.ACL.File != "" {
		hasACL = true
		acl, err := outbounds.NewACLEngineFromFile(c.ACL.File, obs, gLoader)
		if err != nil {
			return configError{Field: "acl.file", Err: err}
		}
		uOb = acl
	} else if len(c.ACL.Inline) > 0 {
		hasACL = true
		acl, err := outbounds.NewACLEngineFromString(strings.Join(c.ACL.Inline, "\n"), obs, gLoader)
		if err != nil {
			return configError{Field: "acl.inline", Err: err}
		}
		uOb = acl
	} else {
		// No ACL, use the first outbound
		uOb = obs[0].Outbound
	}

	// Resolver
	switch strings.ToLower(c.Resolver.Type) {
	case "", "system":
		if hasACL {
			// If the user uses ACL, we must put a resolver in front of it,
			// for IP rules to work on domain requests.
			uOb = outbounds.NewSystemResolver(uOb)
		}
		// Otherwise we can just rely on outbound handling on its own.
	case "tcp":
		if c.Resolver.TCP.Addr == "" {
			return configError{Field: "resolver.tcp.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverTCP(c.Resolver.TCP.Addr, c.Resolver.TCP.Timeout, uOb)
	case "udp":
		if c.Resolver.UDP.Addr == "" {
			return configError{Field: "resolver.udp.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverUDP(c.Resolver.UDP.Addr, c.Resolver.UDP.Timeout, uOb)
	case "tls", "tcp-tls":
		if c.Resolver.TLS.Addr == "" {
			return configError{Field: "resolver.tls.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverTLS(c.Resolver.TLS.Addr, c.Resolver.TLS.Timeout, c.Resolver.TLS.SNI, c.Resolver.TLS.Insecure, uOb)
	case "https", "http":
		if c.Resolver.HTTPS.Addr == "" {
			return configError{Field: "resolver.https.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewDoHResolver(c.Resolver.HTTPS.Addr, c.Resolver.HTTPS.Timeout, c.Resolver.HTTPS.SNI, c.Resolver.HTTPS.Insecure, uOb)
	default:
		return configError{Field: "resolver.type", Err: errors.New("unsupported resolver type")}
	}

	// Speed test
	if c.SpeedTest {
		uOb = outbounds.NewSpeedtestHandler(uOb)
	}

	hyConfig.Outbound = &outbounds.PluggableOutboundAdapter{PluggableOutbound: uOb}
	return nil
}

func (c *ServerConfig) fillBandwidthConfig(hyConfig *server.Config) error {
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = utils.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = utils.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	return nil
}

func (c *ServerConfig) fillIgnoreClientBandwidth(hyConfig *server.Config) error {
	hyConfig.IgnoreClientBandwidth = c.IgnoreClientBandwidth
	return nil
}

func (c *ServerConfig) fillDisableUDP(hyConfig *server.Config) error {
	hyConfig.DisableUDP = c.DisableUDP
	return nil
}

func (c *ServerConfig) fillUDPIdleTimeout(hyConfig *server.Config) error {
	hyConfig.UDPIdleTimeout = c.UDPIdleTimeout
	return nil
}

func (c *ServerConfig) fillAuthenticator(hyConfig *server.Config) error {
	if c.Auth.Type == "" {
		return configError{Field: "auth.type", Err: errors.New("empty auth type")}
	}
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		if c.Auth.Password == "" {
			return configError{Field: "auth.password", Err: errors.New("empty auth password")}
		}
		hyConfig.Authenticator = &auth.PasswordAuthenticator{Password: c.Auth.Password}
		return nil
	case "userpass":
		if len(c.Auth.UserPass) == 0 {
			return configError{Field: "auth.userpass", Err: errors.New("empty auth userpass")}
		}
		hyConfig.Authenticator = auth.NewUserPassAuthenticator(c.Auth.UserPass)
		return nil
	case "http", "https":
		if c.Auth.HTTP.URL == "" {
			return configError{Field: "auth.http.url", Err: errors.New("empty auth http url")}
		}
		hyConfig.Authenticator = auth.NewHTTPAuthenticator(c.Auth.HTTP.URL, c.Auth.HTTP.Insecure)
		return nil
	case "command", "cmd":
		if c.Auth.Command == "" {
			return configError{Field: "auth.command", Err: errors.New("empty auth command")}
		}
		hyConfig.Authenticator = &auth.CommandAuthenticator{Cmd: c.Auth.Command}
		return nil
	default:
		return configError{Field: "auth.type", Err: errors.New("unsupported auth type")}
	}
}

func (c *ServerConfig) fillEventLogger(hyConfig *server.Config) error {
	hyConfig.EventLogger = &serverLogger{log: c.loggerOrDefault()}
	return nil
}

func (c *ServerConfig) fillTrafficLogger(hyConfig *server.Config) error {
	if c.TrafficStats.Listen != "" {
		log := c.loggerOrDefault()
		tss := trafficlogger.NewTrafficStatsServer(c.TrafficStats.Secret)
		hyConfig.TrafficLogger = tss
		go runTrafficStatsServer(c.TrafficStats.Listen, tss, log)
	}
	return nil
}

// fillMasqHandler must be called after fillConn, as we may need to extract the QUIC
// port number from Conn for MasqTCPServer.
func (c *ServerConfig) fillMasqHandler(hyConfig *server.Config) error {
	log := c.loggerOrDefault()
	var handler http.Handler
	switch strings.ToLower(c.Masquerade.Type) {
	case "", "404":
		handler = http.NotFoundHandler()
	case "file":
		if c.Masquerade.File.Dir == "" {
			return configError{Field: "masquerade.file.dir", Err: errors.New("empty file directory")}
		}
		handler = http.FileServer(http.Dir(c.Masquerade.File.Dir))
	case "proxy":
		if c.Masquerade.Proxy.URL == "" {
			return configError{Field: "masquerade.proxy.url", Err: errors.New("empty proxy url")}
		}
		u, err := url.Parse(c.Masquerade.Proxy.URL)
		if err != nil {
			return configError{Field: "masquerade.proxy.url", Err: err}
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return configError{Field: "masquerade.proxy.url", Err: fmt.Errorf("unsupported protocol scheme \"%s\"", u.Scheme)}
		}
		transport := http.DefaultTransport
		if c.Masquerade.Proxy.Insecure {
			transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				// use default configs from http.DefaultTransport
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}
		handler = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				// SetURL rewrites the Host header,
				// but we don't want that if rewriteHost is false
				if !c.Masquerade.Proxy.RewriteHost {
					r.Out.Host = r.In.Host
				}
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Error("HTTP reverse proxy error", zap.Error(err))
				w.WriteHeader(http.StatusBadGateway)
			},
		}
	case "string":
		if c.Masquerade.String.Content == "" {
			return configError{Field: "masquerade.string.content", Err: errors.New("empty string content")}
		}
		if c.Masquerade.String.StatusCode != 0 &&
			(c.Masquerade.String.StatusCode < 200 ||
				c.Masquerade.String.StatusCode > 599 ||
				c.Masquerade.String.StatusCode == 233) {
			// 233 is reserved for Hysteria authentication
			return configError{Field: "masquerade.string.statusCode", Err: errors.New("invalid status code (must be 200-599, except 233)")}
		}
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range c.Masquerade.String.Headers {
				w.Header().Set(k, v)
			}
			if c.Masquerade.String.StatusCode != 0 {
				w.WriteHeader(c.Masquerade.String.StatusCode)
			} else {
				w.WriteHeader(http.StatusOK) // Use 200 OK by default
			}
			_, _ = w.Write([]byte(c.Masquerade.String.Content))
		})
	default:
		return configError{Field: "masquerade.type", Err: errors.New("unsupported masquerade type")}
	}
	hyConfig.MasqHandler = &masqHandlerLogWrapper{H: handler, QUIC: true, log: log}

	if c.Masquerade.ListenHTTP != "" || c.Masquerade.ListenHTTPS != "" {
		if c.Masquerade.ListenHTTP != "" && c.Masquerade.ListenHTTPS == "" {
			return configError{Field: "masquerade.listenHTTPS", Err: errors.New("having only HTTP server without HTTPS is not supported")}
		}
		s := masq.MasqTCPServer{
			QUICPort:  extractPortFromAddr(hyConfig.Conn.LocalAddr().String()),
			HTTPSPort: extractPortFromAddr(c.Masquerade.ListenHTTPS),
			Handler:   &masqHandlerLogWrapper{H: handler, QUIC: false, log: log},
			TLSConfig: &tls.Config{
				Certificates:   hyConfig.TLSConfig.Certificates,
				GetCertificate: hyConfig.TLSConfig.GetCertificate,
			},
			ForceHTTPS: c.Masquerade.ForceHTTPS,
		}
		go runMasqTCPServer(&s, c.Masquerade.ListenHTTP, c.Masquerade.ListenHTTPS, log)
	}
	return nil
}

// Config validates the fields and returns a ready-to-use Hysteria server config
func (c *ServerConfig) Config() (*server.Config, error) {
	hyConfig := &server.Config{}
	fillers := []func(*server.Config) error{
		c.fillConn,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillRequestHook,
		c.fillOutboundConfig,
		c.fillBandwidthConfig,
		c.fillIgnoreClientBandwidth,
		c.fillDisableUDP,
		c.fillUDPIdleTimeout,
		c.fillAuthenticator,
		c.fillEventLogger,
		c.fillTrafficLogger,
		c.fillMasqHandler,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}

	return hyConfig, nil
}

func runTrafficStatsServer(listen string, handler http.Handler, log *zap.Logger) {
	if log == nil {
		log = zap.L().Named("hysteria")
	}
	log.Info("traffic stats server up and running", zap.String("listen", listen))
	if err := correctnet.HTTPListenAndServe(listen, handler); err != nil {
		log.Fatal("failed to serve traffic stats", zap.Error(err))
	}
}

func runMasqTCPServer(s *masq.MasqTCPServer, httpAddr, httpsAddr string, log *zap.Logger) {
	if log == nil {
		log = zap.L().Named("hysteria")
	}
	errChan := make(chan error, 2)
	if httpAddr != "" {
		go func() {
			log.Info("masquerade HTTP server up and running", zap.String("listen", httpAddr))
			errChan <- s.ListenAndServeHTTP(httpAddr)
		}()
	}
	if httpsAddr != "" {
		go func() {
			log.Info("masquerade HTTPS server up and running", zap.String("listen", httpsAddr))
			errChan <- s.ListenAndServeHTTPS(httpsAddr)
		}()
	}
	err := <-errChan
	if err != nil {
		log.Fatal("failed to serve masquerade HTTP(S)", zap.Error(err))
	}
}

type serverLogger struct {
	log *zap.Logger
}

func (l *serverLogger) logger() *zap.Logger {
	if l.log != nil {
		return l.log
	}
	return zap.L().Named("hysteria")
}

func (l *serverLogger) Connect(addr net.Addr, id string, tx uint64) {
	l.logger().Info("client connected", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint64("tx", tx))
}

func (l *serverLogger) Disconnect(addr net.Addr, id string, err error) {
	l.logger().Info("client disconnected", zap.String("addr", addr.String()), zap.String("id", id), zap.Error(err))
}

func (l *serverLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	l.logger().Debug("TCP request", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	log := l.logger()
	if err == nil {
		log.Debug("TCP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
	} else {
		log.Warn("TCP error", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *serverLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	l.logger().Debug("UDP request", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	log := l.logger()
	if err == nil {
		log.Debug("UDP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID))
	} else {
		log.Warn("UDP error", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.Error(err))
	}
}

type masqHandlerLogWrapper struct {
	H    http.Handler
	QUIC bool
	log  *zap.Logger
}

func (m *masqHandlerLogWrapper) logger() *zap.Logger {
	if m.log != nil {
		return m.log
	}
	return zap.L().Named("hysteria")
}

func (m *masqHandlerLogWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.logger().Debug("masquerade request",
		zap.String("addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("url", r.URL.String()),
		zap.Bool("quic", m.QUIC))
	m.H.ServeHTTP(w, r)
}

func extractPortFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
