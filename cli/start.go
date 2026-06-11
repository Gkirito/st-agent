package cli

import (
	"context"
	"time"

	"github.com/gkirito/st-agent/config"
	"github.com/gkirito/st-agent/tunnel/anytls"
	"github.com/gkirito/st-agent/tunnel/common"
	"github.com/gkirito/st-agent/tunnel/hysteria"
	"github.com/gkirito/st-agent/tunnel/xray"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type tunnelDef struct {
	name        string
	shouldStart func(*config.Config) bool
	newServer   func(*config.Config) common.TunnelServer
	needReload  func(common.TunnelServer, *config.Config) (bool, error)
}

var tunnels = []tunnelDef{
	{
		name:        "xray",
		shouldStart: func(c *config.Config) bool { return c.NeedStartXrayServer() },
		newServer:   func(c *config.Config) common.TunnelServer { return xray.NewXrayServer(c) },
		needReload: func(s common.TunnelServer, c *config.Config) (bool, error) {
			return s.(*xray.XrayServer).NeedReload(c)
		},
	},
	{
		name:        "hysteria",
		shouldStart: func(c *config.Config) bool { return c.NeedStartHysteriaServer() },
		newServer: func(c *config.Config) common.TunnelServer {
			return hysteria.NewHysteriaServer(c.HysteriaConfig, c.SyncTrafficEndPoint)
		},
		needReload: func(s common.TunnelServer, c *config.Config) (bool, error) {
			return s.(*hysteria.HysteriaServer).NeedReload(c.HysteriaConfig)
		},
	},
	{
		name:        "anytls",
		shouldStart: func(c *config.Config) bool { return c.NeedStartAnytlsServer() },
		newServer: func(c *config.Config) common.TunnelServer {
			return anytls.NewAnytlsServer(c.AnytlsConfig, c.SyncTrafficEndPoint)
		},
		needReload: func(s common.TunnelServer, c *config.Config) (bool, error) {
			return s.(*anytls.AnytlsServer).NeedReload(c.AnytlsConfig)
		},
	},
}

func startSTAgent(ctx context.Context, cfg *config.Config, atomicLevel zap.AtomicLevel) {
	log := zap.S().Named("cli")
	instances := make([]common.TunnelServer, len(tunnels))

	for i, def := range tunnels {
		if def.shouldStart(cfg) {
			s := def.newServer(cfg)
			if err := s.Setup(); err != nil {
				log.Fatalf("Setup %s meet err=%v", def.name, err)
			}
			if err := s.Start(ctx); err != nil {
				log.Fatalf("Start %s meet err=%v", def.name, err)
			}
			instances[i] = s
		}
	}

	if cfg.ReloadInterval > 0 {
		l := zap.S().Named("cfg-watcher")
		go func() {
			ticker := time.NewTicker(time.Second * time.Duration(cfg.ReloadInterval))
			defer ticker.Stop()

			startTunnel := func(def tunnelDef, cfg *config.Config) common.TunnelServer {
				s := def.newServer(cfg)
				if err := s.Setup(); err != nil {
					l.Error("Setup failed", zap.String("server", def.name), zap.Error(err))
					return nil
				}
				if err := s.Start(ctx); err != nil {
					l.Error("Start failed", zap.String("server", def.name), zap.Error(err))
					return nil
				}
				return s
			}

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					newCfg := config.NewConfig(cfg.PATH)
					if err := newCfg.LoadConfig(false); err != nil {
						l.Error("Reload Config meet error will retry in next loop", zap.Error(err))
						continue
					}
					mergeACMECLI(newCfg)

					if newCfg.LogLevel != cfg.LogLevel && newCfg.LogLevel != "" {
						var lvl zapcore.Level
						if err := lvl.UnmarshalText([]byte(newCfg.LogLevel)); err == nil {
							atomicLevel.SetLevel(lvl)
							l.Info("LogLevel updated", zap.String("level", newCfg.LogLevel))
						}
					}

					// Dynamic ReloadInterval: reset ticker on change, ignore <=0
					if newCfg.ReloadInterval != cfg.ReloadInterval && newCfg.ReloadInterval > 0 {
						ticker.Reset(time.Second * time.Duration(newCfg.ReloadInterval))
					}

					for i, def := range tunnels {
						wasRunning := instances[i] != nil
						shouldRun := def.shouldStart(newCfg)

						if wasRunning && !shouldRun {
							l.Info("stopping removed tunnel", zap.String("server", def.name))
							instances[i].Stop()
							instances[i] = nil
							continue
						}

						if !shouldRun {
							continue
						}

						if !wasRunning {
							l.Info("starting new tunnel", zap.String("server", def.name))
							instances[i] = startTunnel(def, newCfg)
							continue
						}

						// wasRunning && shouldRun
						if needReload, err := def.needReload(instances[i], newCfg); err != nil {
							l.Error("check need reload meet error", zap.String("server", def.name), zap.Error(err))
						} else if needReload {
							l.Info("reloading tunnel", zap.String("server", def.name))
							instances[i].Stop()
							instances[i] = startTunnel(def, newCfg)
							if instances[i] != nil {
								l.Info("tunnel reloaded", zap.String("server", def.name))
							}
						}
					}

					cfg = newCfg
				}
			}
		}()
	}
}
