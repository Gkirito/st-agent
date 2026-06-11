package cli

import (
	"os"
	"strings"

	"github.com/gkirito/st-agent/config"
	stTls "github.com/gkirito/st-agent/tool/tls"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func loadConfig() (cfg *config.Config, err error) {
	if ConfigPath != "" {
		cfg = config.NewConfig(ConfigPath)
		if err := cfg.LoadConfig(true); err != nil {
			return nil, err
		}
	} else {
		cfg = &config.Config{
			PATH:           ConfigPath,
			LogLevel:       LogLevel,
			ReloadInterval: ConfigReloadInterval,
			// RelayConfigs: []*conf.Config{
			// 	{
			// 		Listen:        LocalAddr,
			// 		ListenType:    ListenType,
			// 		TransportType: TransportType,
			// 	},
			// },
		}
		if err := cfg.Adjust(); err != nil {
			return nil, err
		}
	}

	// Merge CLI ACME flags into config (CLI takes precedence over config file)
	mergeACMECLI(cfg)

	return cfg, nil
}

// mergeACMECLI overlays CLI ACME flag values onto the config's ACME section.
// CLI flags take precedence over config file values.
func mergeACMECLI(cfg *config.Config) {
	// Overlay CLI flags when cfg.ACME already exists from config file,
	// or when at least one primary ACME flag is set on the CLI.
	hasCLI := len(ACMEFlagDomains.Value()) > 0 ||
		ACMEFlagEmail != "" ||
		ACMEFlagCA != "" ||
		ACMEFlagChallenge != "" ||
		ACMEFlagDNSName != "" ||
		len(ACMEFlagDNSConfig.Value()) > 0 ||
		ACMEFlagZeroSSLEAB != "" ||
		ACMEFlagKeyType != "" ||
		ACMEFlagDir != "" ||
		ACMEFlagHTTPPort > 0 ||
		ACMEFlagTLSALPNPort > 0 ||
		ACMEFlagFallback

	if cfg.ACME == nil && !hasCLI {
		return
	}

	if cfg.ACME == nil {
		cfg.ACME = &stTls.CertMagicConfig{}
	}

	if v := ACMEFlagDomains.Value(); len(v) > 0 {
		cfg.ACME.Domains = v
	}
	if ACMEFlagEmail != "" {
		cfg.ACME.Email = ACMEFlagEmail
	}
	if ACMEFlagCA != "" {
		cfg.ACME.CA = ACMEFlagCA
	}
	if ACMEFlagKeyType != "" {
		cfg.ACME.KeyType = ACMEFlagKeyType
	}
	if ACMEFlagDir != "" {
		cfg.ACME.Dir = ACMEFlagDir
	}
	if ACMEFlagChallenge != "" {
		cfg.ACME.Challenge = ACMEFlagChallenge
	}
	if ACMEFlagHTTPPort > 0 {
		cfg.ACME.HTTPPort = ACMEFlagHTTPPort
	}
	if ACMEFlagTLSALPNPort > 0 {
		cfg.ACME.TLSALPNPort = ACMEFlagTLSALPNPort
	}
	if ACMEFlagFallback {
		cfg.ACME.Fallback = true
	}

	// DNS provider name
	if ACMEFlagDNSName != "" {
		if cfg.ACME.DNS == nil {
			cfg.ACME.DNS = &stTls.CertMagicDNSConfig{}
		}
		cfg.ACME.DNS.Name = ACMEFlagDNSName
	}

	// DNS provider config — merges into existing config from file
	if dnsConfig := ACMEFlagDNSConfig.Value(); len(dnsConfig) > 0 {
		if cfg.ACME.DNS == nil {
			cfg.ACME.DNS = &stTls.CertMagicDNSConfig{}
		}
		if cfg.ACME.DNS.Config == nil {
			cfg.ACME.DNS.Config = make(map[string]string, len(dnsConfig))
		}
		for _, kv := range dnsConfig {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				cfg.ACME.DNS.Config[parts[0]] = parts[1]
			}
		}
	}

	// ZeroSSL EAB: format "key_id:hmac_key"
	if ACMEFlagZeroSSLEAB != "" {
		parts := strings.SplitN(ACMEFlagZeroSSLEAB, ":", 2)
		if len(parts) == 2 {
			cfg.ACME.EABKeyID = parts[0]
			cfg.ACME.EABMACKey = parts[1]
		}
	}
}

func initLogger(cfg *config.Config) (zap.AtomicLevel, error) {
	level := zapcore.InfoLevel
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return zap.NewAtomicLevelAt(zapcore.InfoLevel), err
	}
	atomicLevel := zap.NewAtomicLevelAt(level)
	writers := []zapcore.WriteSyncer{zapcore.AddSync(os.Stderr)}
	encoder := zapcore.EncoderConfig{
		TimeKey:     "ts",
		LevelKey:    "level",
		MessageKey:  "msg",
		NameKey:     "name",
		EncodeLevel: zapcore.LowercaseColorLevelEncoder,
		EncodeTime:  zapcore.RFC3339TimeEncoder,
		EncodeName:  zapcore.FullNameEncoder,
	}
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoder),
		zapcore.NewMultiWriteSyncer(writers...),
		atomicLevel,
	)
	l := zap.New(core)
	zap.ReplaceGlobals(l)
	return atomicLevel, nil
}
