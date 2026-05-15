package cli

import (
	"context"
	"time"

	"github.com/gkirito/st-agent/config"
	"github.com/gkirito/st-agent/tunnel/anytls"
	"github.com/gkirito/st-agent/tunnel/hysteria"
	"github.com/gkirito/st-agent/tunnel/xray"
	"go.uber.org/zap"
)

func startSTAgent(ctx context.Context, cfg *config.Config) {
	log := zap.S().Named("cli")
	var (
		xrayS     *xray.XrayServer
		hysteriaS *hysteria.HysteriaServer
		anytlsS   *anytls.AnytlsServer
	)
	if cfg.NeedStartXrayServer() {
		xrayS = xray.NewXrayServer(cfg)
		if err := xrayS.Setup(); err != nil {
			log.Fatalf("Setup XrayServer meet err=%v", err)
		}
		if err := xrayS.Start(ctx); err != nil {
			log.Fatalf("Start XrayServer meet err=%v", err)
		}
	}
	if cfg.NeedStartHysteriaServer() {
		hysteriaS = hysteria.NewHysteriaServer(cfg.HysteriaConfig, cfg.SyncTrafficEndPoint)
		if err := hysteriaS.Setup(); err != nil {
			log.Fatalf("Setup HysteriaServer meet err=%v", err)
		}
		if err := hysteriaS.Start(ctx); err != nil {
			log.Fatalf("Start HysteriaServer meet err=%v", err)
		}
	}
	if cfg.NeedStartAnytlsServer() {
		anytlsS = anytls.NewAnytlsServer(cfg.AnytlsConfig, cfg.SyncTrafficEndPoint)
		if err := anytlsS.Setup(); err != nil {
			log.Fatalf("Setup AnytlsServer meet err=%v", err)
		}
		if err := anytlsS.Start(ctx); err != nil {
			log.Fatalf("Start AnytlsServer meet err=%v", err)
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
						// TODO refine
						l.Error("Reload Config meet error will retry in next loop", zap.Error(err))
						continue
					}
					if cfg.NeedStartXrayServer() {
						if xrayS != nil {
							if needReload, err := xrayS.NeedReload(newCfg); err != nil {
								l.Error("check need reload meet error", zap.Error(err))
							} else {
								if needReload {
									cfg = newCfg
									if err := xrayS.Reload(); err != nil {
										l.Error("Reload Xray Server meet error", zap.Error(err))
									}
									l.Warn("Reload Xray Server success exit watcher ...")
									return
								}
							}
						} else {
							xrayS = xray.NewXrayServer(cfg)
							if err := xrayS.Setup(); err != nil {
								l.Error("Setup XrayServer meet error", zap.Error(err))
								xrayS = nil
							} else {
								if err := xrayS.Start(ctx); err != nil {
									l.Error("Start XrayServer meet error", zap.Error(err))
									xrayS = nil
								}
							}
						}
					}
					if cfg.NeedStartHysteriaServer() {
						if hysteriaS != nil {
							if needReload, err := hysteriaS.NeedReload(cfg.HysteriaConfig); err != nil {
								l.Error("check need reload meet error", zap.Error(err))
							} else {
								if needReload {
									cfg = newCfg
									if err := hysteriaS.Reload(); err != nil {
										l.Error("Reload Hysteria Server meet error", zap.Error(err))
									}
									l.Warn("Reload Hysteria Server success exit watcher ...")
									return
								}
							}
						} else {
							hysteriaS = hysteria.NewHysteriaServer(cfg.HysteriaConfig, cfg.SyncTrafficEndPoint)
							if err := hysteriaS.Setup(); err != nil {
								l.Error("Setup HysteriaServer meet error", zap.Error(err))
								hysteriaS = nil
							} else {
								if err := hysteriaS.Start(ctx); err != nil {
									l.Error("Start HysteriaServer meet error", zap.Error(err))
									hysteriaS = nil
								}
							}
						}
					}
					if cfg.NeedStartAnytlsServer() {
						if anytlsS != nil {
							if needReload, err := anytlsS.NeedReload(newCfg.AnytlsConfig); err != nil {
								l.Error("check anytls need reload meet error", zap.Error(err))
							} else {
								if needReload {
									cfg = newCfg
									if err := anytlsS.Reload(); err != nil {
										l.Error("Reload Anytls Server meet error", zap.Error(err))
									}
									l.Warn("Reload Anytls Server success exit watcher ...")
									return
								}
							}
						} else {
							anytlsS = anytls.NewAnytlsServer(cfg.AnytlsConfig, cfg.SyncTrafficEndPoint)
							if err := anytlsS.Setup(); err != nil {
								l.Error("Setup AnytlsServer meet error", zap.Error(err))
								anytlsS = nil
							} else {
								if err := anytlsS.Start(ctx); err != nil {
									l.Error("Start AnytlsServer meet error", zap.Error(err))
									anytlsS = nil
								}
							}
						}
					}
				}
			}
		}()
	}
}
