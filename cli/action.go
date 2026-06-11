package cli

import (
	"os/signal"
	"syscall"

	cli "github.com/urfave/cli/v2"
	stTls "github.com/gkirito/st-agent/tool/tls"
	"go.uber.org/zap"
)

func action(ctx *cli.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	atomicLevel, err := initLogger(cfg)
	if err != nil {
		return err
	}
	mainCtx, stop := signal.NotifyContext(ctx.Context, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Initialize certmagic if ACME is configured (CLI flags or config file).
	// Must happen before tunnel start so certs are ready.
	if cfg.ACME != nil && len(cfg.ACME.Domains) > 0 {
		l := zap.L().Named("certmagic")
		if err := stTls.InitCertMagic(mainCtx, cfg.ACME, l); err != nil {
			if cfg.ACME.Fallback {
				l.Warn("certmagic init failed, using self-signed fallback", zap.Error(err))
				_ = stTls.InitTlsCfg()
			} else {
				return err
			}
		}
	} else {
		// Pre-generate self-signed cert if ACME is not configured.
		if err := stTls.InitTlsCfg(); err != nil {
			return err
		}
	}

	startSTAgent(mainCtx, cfg, atomicLevel)

	<-mainCtx.Done()

	return nil
}
