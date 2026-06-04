package cli

import (
	cli "github.com/urfave/cli/v2"
)

var (
	ConfigPath           string
	SystemFilePath       = "/etc/systemd/system/stagent.service"
	LogLevel             string
	ConfigReloadInterval int

	// ACME (certmagic) CLI flags — overlays config file values.
	ACMEFlagDomains  cli.StringSlice
	ACMEFlagEmail    string
	ACMEFlagCA       string
	ACMEFlagKeyType  string
	ACMEFlagDir      string
	ACMEFlagChallenge string
	ACMEFlagDNSName  string
	ACMEFlagDNSConfig cli.StringSlice
	ACMEFlagHTTPPort  int
	ACMEFlagTLSALPNPort int
	ACMEFlagFallback bool
	ACMEFlagZeroSSLEAB string
)

var RootFlags = []cli.Flag{
	&cli.StringFlag{
		Name:        "config",
		Usage:       "配置文件地址，支持文件类型或 http api",
		Aliases:     []string{"c"},
		EnvVars:     []string{"STAGENT_CONFIG_FILE"},
		Destination: &ConfigPath,
	},
	&cli.StringFlag{
		Name:        "log_level",
		Usage:       "log level",
		Aliases:     []string{"ll"},
		EnvVars:     []string{"STAGENT_LOG_LEVEL"},
		Destination: &LogLevel,
		DefaultText: "info",
	},
	&cli.IntFlag{
		Name:        "config_reload_interval",
		Usage:       "config reload interval",
		EnvVars:     []string{"STAGENT_CONFIG_RELOAD_INTERVAL"},
		Aliases:     []string{"cri"},
		Destination: &ConfigReloadInterval,
		DefaultText: "60",
	},

	// ---- ACME / certmagic flags ----
	&cli.StringSliceFlag{
		Name:        "acme-domain",
		Usage:       "ACME domain(s) (repeatable)",
		EnvVars:     []string{"STAGENT_ACME_DOMAIN"},
		Destination: &ACMEFlagDomains,
	},
	&cli.StringFlag{
		Name:        "acme-email",
		Usage:       "ACME account email",
		EnvVars:     []string{"STAGENT_ACME_EMAIL"},
		Destination: &ACMEFlagEmail,
	},
	&cli.StringFlag{
		Name:        "acme-ca",
		Usage:       "ACME CA: letsencrypt (default) or zerossl",
		EnvVars:     []string{"STAGENT_ACME_CA"},
		Destination: &ACMEFlagCA,
	},
	&cli.StringFlag{
		Name:        "acme-key-type",
		Usage:       "Certificate key type: ecdsa (default), rsa2048, rsa4096, ed25519",
		EnvVars:     []string{"STAGENT_ACME_KEY_TYPE"},
		Destination: &ACMEFlagKeyType,
	},
	&cli.StringFlag{
		Name:        "acme-dir",
		Usage:       "Certmagic storage directory (default: ./certmagic-data)",
		EnvVars:     []string{"STAGENT_ACME_DIR"},
		Destination: &ACMEFlagDir,
	},
	&cli.StringFlag{
		Name:        "acme-challenge",
		Usage:       "ACME challenge type: http (default), tls, dns",
		EnvVars:     []string{"STAGENT_ACME_CHALLENGE"},
		Destination: &ACMEFlagChallenge,
	},
	&cli.StringFlag{
		Name:        "acme-dns",
		Usage:       "DNS provider for dns-01 challenge: cloudflare,duckdns,gandi,godaddy",
		EnvVars:     []string{"STAGENT_ACME_DNS"},
		Destination: &ACMEFlagDNSName,
	},
	&cli.StringSliceFlag{
		Name:        "acme-dns-config",
		Usage:       "DNS provider config as key=value pairs (repeatable, e.g. 'api_token=xxx')",
		EnvVars:     []string{"STAGENT_ACME_DNS_CONFIG"},
		Destination: &ACMEFlagDNSConfig,
	},
	&cli.IntFlag{
		Name:        "acme-http-port",
		Usage:       "Alternate HTTP-01 challenge port",
		EnvVars:     []string{"STAGENT_ACME_HTTP_PORT"},
		Destination: &ACMEFlagHTTPPort,
	},
	&cli.IntFlag{
		Name:        "acme-tls-alpn-port",
		Usage:       "Alternate TLS-ALPN challenge port",
		EnvVars:     []string{"STAGENT_ACME_TLS_ALPN_PORT"},
		Destination: &ACMEFlagTLSALPNPort,
	},
	&cli.BoolFlag{
		Name:        "acme-fallback",
		Usage:       "Fall back to self-signed on ACME failure",
		EnvVars:     []string{"STAGENT_ACME_FALLBACK"},
		Destination: &ACMEFlagFallback,
	},
	&cli.StringFlag{
		Name:        "acme-zerossl-eab",
		Usage:       "ZeroSSL EAB credentials as key_id:hmac_key",
		EnvVars:     []string{"STAGENT_ACME_ZEROSSL_EAB"},
		Destination: &ACMEFlagZeroSSLEAB,
	},
}

func NewApp() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		// println("Welcome to safetunnel agent (st-agent is a network relay tool and a typo)")
		// println(fmt.Sprintf("Version=%s", constant.Version))
		// println(fmt.Sprintf("GitBranch=%s", constant.GitBranch))
		// println(fmt.Sprintf("GitRevision=%s", constant.GitRevision))
		// println(fmt.Sprintf("BuildTime=%s", constant.BuildTime))
	}
	app := cli.NewApp()
	app.Name = "st-agent"
	app.Flags = RootFlags
	// app.Version = constant.Version
	app.Commands = []*cli.Command{InstallCMD}
	app.Usage = "st-agent is a network relay tool and a typo :)"
	app.Action = action
	return app
}
