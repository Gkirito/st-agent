package cli

import (
	"os/signal"
	"syscall"

	cli "github.com/urfave/cli/v2"
)

func action(ctx *cli.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	err = initLogger(cfg)
	if err != nil {
		return err
	}
	mainCtx, stop := signal.NotifyContext(ctx.Context, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startSTAgent(mainCtx, cfg)

	<-mainCtx.Done()

	return nil
}
