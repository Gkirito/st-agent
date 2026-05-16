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

func startSTAgent(ctx context.Context, cfg *config.Config) {
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
					for i, def := range tunnels {
						if def.shouldStart(cfg) {
							if instances[i] != nil {
								if needReload, err := def.needReload(instances[i], newCfg); err != nil {
									l.Error("check need reload meet error", zap.String("server", def.name), zap.Error(err))
								} else if needReload {
									cfg = newCfg
									if err := instances[i].Reload(); err != nil {
										l.Error("Reload meet error", zap.String("server", def.name), zap.Error(err))
									}
									l.Warn("Reload success exit watcher", zap.String("server", def.name))
									return
								}
							} else {
								s := def.newServer(cfg)
								if err := s.Setup(); err != nil {
									l.Error("Setup meet error", zap.String("server", def.name), zap.Error(err))
								} else {
									if err := s.Start(ctx); err != nil {
										l.Error("Start meet error", zap.String("server", def.name), zap.Error(err))
									} else {
										instances[i] = s
									}
								}
							}
						}
					}
				}
			}
		}()
	}
}
