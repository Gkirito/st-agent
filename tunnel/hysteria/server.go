package hysteria

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/gkirito/st-agent/tool/tls"
	"github.com/gkirito/st-agent/tunnel/common"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var _ common.TunnelServer = (*HysteriaServer)(nil)

type HysteriaServer struct {
	l                   *zap.Logger
	cfg                 *ServerConfig
	syncTrafficEndPoint string

	up       *UserPool
	fallBack *http.Server
	auth     *http.Server
	instance server.Server

	mainCtx context.Context
}

func NewHysteriaServer(cfg *ServerConfig, syncTrafficEndPoint string) *HysteriaServer {
	return &HysteriaServer{l: zap.L().Named("hysteria"), cfg: cfg, syncTrafficEndPoint: syncTrafficEndPoint}
}

func (hs *HysteriaServer) Name() string { return "hysteria" }

func (hs *HysteriaServer) Setup() error {
	hs.l.Debug("hysteria Setup")
	hs.cfg.WithLogger(hs.l)
	if err := tls.InitTlsCfg(); err != nil {
		return err
	}
	hs.cfg.TrafficStats.Listen = "127.0.0.1:8122"
	hs.cfg.TrafficStats.Secret = uuid.New().String()
	hs.l.Debug("hysteria server traffic api key: ", zap.String("key", hs.cfg.TrafficStats.Secret))
	hs.cfg.Auth.Type = "http"
	hs.cfg.Auth.HTTP.Insecure = false
	hs.cfg.Auth.HTTP.URL = "http://127.0.0.1:8123/auth"
	hs.cfg.TLS = &serverConfigTLS{
		SNIGuard: "disable",
		SelfTls:  &tls.DefaultTLSConfig.Certificates[0],
	}

	coreCfg, err := hs.cfg.Config()
	if err != nil {
		return err
	}
	hs.instance, err = server.NewServer(coreCfg)
	if err != nil {
		return err
	}

	if hs.syncTrafficEndPoint == "" {
		return errors.New("syncTrafficEndPoint is null")
	}
	hs.up = NewUserPool(hs.cfg.TrafficStats.Listen, hs.syncTrafficEndPoint, "", hs.cfg.TrafficStats.Secret)
	hs.auth, err = NewHyServer("127.0.0.1", 8123, hs.up)
	if err != nil {
		return err
	}
	return nil
}

func (hs *HysteriaServer) Stop() {
	hs.l.Warn("Stop Hysteria Server now...")
	if hs.instance != nil {
		if err := hs.instance.Close(); err != nil {
			hs.l.Error("stop instance meet error", zap.Error(err))
		}
	}
	if hs.fallBack != nil {
		if err := hs.fallBack.Close(); err != nil {
			hs.l.Error("stop fallback server meet error", zap.Error(err))
		}
	}
	if hs.auth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := hs.auth.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			hs.l.Error("stop auth server meet error", zap.Error(err))
		}
	}
	if hs.up != nil {
		hs.up.Stop()
	}
}

func (hs *HysteriaServer) Start(ctx context.Context) error {
	hs.l.Info("Start Hysteria Server now...")
	if hs.auth != nil {
		go func() {
			hs.l.Info("start auth http server", zap.String("addr", hs.auth.Addr))
			if err := hs.auth.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				hs.l.Error("auth server stopped unexpectedly", zap.Error(err))
			}
		}()
	}

	go func() {
		err := hs.instance.Serve()
		if err != nil {
			hs.l.Error("hysteria server stopped unexpectedly", zap.Error(err))
		}
	}()
	if hs.fallBack != nil {
		go func() {
			if err := hs.fallBack.ListenAndServe(); err != nil {
				hs.l.Error("fallback server meet error", zap.Error(err))
			}
		}()
	}

	if hs.up != nil {
		if err := hs.up.Start(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (hs *HysteriaServer) NeedReload(newCfg *ServerConfig) (bool, error) {
	if newCfg.Listen != hs.cfg.Listen {
		hs.l.Warn("find listen changed reload hysteria server now...",
			zap.String("old", hs.cfg.Listen),
			zap.String("new", newCfg.Listen))
		return true, nil
	}
	if newCfg.DisableUDP != hs.cfg.DisableUDP {
		hs.l.Warn("find disable_udp changed reload hysteria server now...",
			zap.Bool("old", hs.cfg.DisableUDP),
			zap.Bool("new", newCfg.DisableUDP))
		return true, nil
	}
	if newCfg.IgnoreClientBandwidth != hs.cfg.IgnoreClientBandwidth {
		hs.l.Warn("find ignore_client_bandwidth_limit changed reload hysteria server now...",
			zap.Bool("old", hs.cfg.IgnoreClientBandwidth),
			zap.Bool("new", newCfg.IgnoreClientBandwidth))
		return true, nil
	}
	if newCfg.SpeedTest != hs.cfg.SpeedTest {
		hs.l.Warn("find speed_test changed reload hysteria server now...",
			zap.Bool("old", hs.cfg.SpeedTest),
			zap.Bool("new", newCfg.SpeedTest))
		return true, nil
	}
	if newCfg.UDPIdleTimeout != hs.cfg.UDPIdleTimeout {
		hs.l.Warn("find udp_idle_timeout changed reload hysteria server now...",
			zap.Duration("old", hs.cfg.UDPIdleTimeout),
			zap.Duration("new", newCfg.UDPIdleTimeout))
		return true, nil
	}
	if newCfg.Bandwidth.Down != hs.cfg.Bandwidth.Down || newCfg.Bandwidth.Up != hs.cfg.Bandwidth.Up {
		return true, nil
	}
	return false, nil
}

func (hs *HysteriaServer) Reload() error {
	hs.l.Warn("Reload Hysteria Server now...")
	hs.Stop()
	if err := hs.Setup(); err != nil {
		return err
	}
	if err := hs.Start(hs.mainCtx); err != nil {
		return err
	}
	return nil
}
