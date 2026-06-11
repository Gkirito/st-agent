package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"anytls/proxy/padding"
	stTls "github.com/gkirito/st-agent/tool/tls"
	"github.com/gkirito/st-agent/tunnel/common"

	"go.uber.org/zap"
)

var _ common.TunnelServer = (*AnytlsServer)(nil)

type AnytlsServer struct {
	l   *zap.Logger
	cfg *ServerConfig

	up       *UserPool
	listener net.Listener

	syncTrafficEndPoint string
	mainCtx             context.Context
}

func NewAnytlsServer(cfg *ServerConfig, syncTrafficEndPoint string) *AnytlsServer {
	return &AnytlsServer{
		l:                   zap.L().Named("anytls"),
		cfg:                 cfg,
		syncTrafficEndPoint: syncTrafficEndPoint,
	}
}

func (as *AnytlsServer) Name() string { return "anytls" }

func (as *AnytlsServer) Setup() error {
	as.l.Debug("anytls Setup")
	if as.cfg.Listen == "" {
		return errors.New("anytls listen address is empty")
	}
	if as.syncTrafficEndPoint == "" {
		return errors.New("syncTrafficEndPoint is empty")
	}

	if as.cfg.PaddingScheme != "" {
		if !padding.UpdatePaddingScheme([]byte(as.cfg.PaddingScheme)) {
			as.l.Warn("invalid padding_scheme, using default")
		} else {
			as.l.Debug("custom padding scheme applied")
		}
	}

	if err := stTls.InitTlsCfg(); err != nil {
		return err
	}
	as.up = NewUserPool(as.syncTrafficEndPoint)
	return nil
}

func (as *AnytlsServer) Start(ctx context.Context) error {
	as.l.Info("Start Anytls Server", zap.String("listen", as.cfg.Listen))

	tlsConfig := &tls.Config{
		GetCertificate: stTls.GetCertificate,
	}

	listener, err := net.Listen("tcp", as.cfg.Listen)
	if err != nil {
		return err
	}
	as.listener = listener

	if err := as.up.Start(ctx); err != nil {
		listener.Close()
		return err
	}

	if as.mainCtx == nil {
		as.mainCtx = ctx
	}

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					as.l.Error("anytls accept failed", zap.Error(err))
					return
				}
			}
			go handleTcpConnection(ctx, c, tlsConfig, as.up)
		}
	}()

	return nil
}

func (as *AnytlsServer) Stop() {
	as.l.Warn("Stop Anytls Server now...")
	if as.listener != nil {
		as.listener.Close()
	}
	if as.up != nil {
		as.up.Stop()
	}
}

func (as *AnytlsServer) NeedReload(newCfg *ServerConfig) (bool, error) {
	if newCfg.Listen != as.cfg.Listen {
		as.l.Warn("find listen changed, reload anytls server",
			zap.String("old", as.cfg.Listen),
			zap.String("new", newCfg.Listen))
		return true, nil
	}
	if newCfg.PaddingScheme != as.cfg.PaddingScheme {
		as.l.Info("padding_scheme changed, updating atomically")
		if newCfg.PaddingScheme != "" {
			if padding.UpdatePaddingScheme([]byte(newCfg.PaddingScheme)) {
				as.cfg.PaddingScheme = newCfg.PaddingScheme
				as.l.Debug("padding_scheme updated successfully")
			} else {
				as.l.Warn("invalid padding_scheme in new config, keeping current")
			}
		} else {
			as.l.Warn("padding_scheme cleared, restart required to reset to default")
			as.cfg.PaddingScheme = newCfg.PaddingScheme
		}
	}
	return false, nil
}

func (as *AnytlsServer) Reload() error {
	as.l.Warn("Reload Anytls Server now...")
	as.Stop()
	if err := as.Setup(); err != nil {
		return err
	}
	if err := as.Start(as.mainCtx); err != nil {
		return err
	}
	return nil
}
