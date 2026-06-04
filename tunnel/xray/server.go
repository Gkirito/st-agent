package xray

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gkirito/st-agent/config"
	"github.com/gkirito/st-agent/tool/tls"
	"github.com/gkirito/st-agent/tunnel/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/main/distro/all" // register all features
	"go.uber.org/zap"
)

func buildXrayInstanceCfg(cfg *conf.Config) (*core.Config, error) {
	for _, inbound := range cfg.InboundConfigs {
		// add tls certs for trojan
		if inbound.Tag == XrayTrojanProxyTag || inbound.Tag == XrayVmessProxyTag || inbound.Tag == XrayVlessProxyTag {
			if err := tls.InitTlsCfg(); err != nil {
				return nil, err
			}
			// Note: Xray receives a static PEM snapshot at config-build time.
			// After certmagic renewals, xray must be reloaded (via config reload)
			// to pick up the updated certificate. For always-current certificates,
			// prefer anytls or hysteria tunnels which use the dynamic GetCertificate
			// callback.
			getCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			certPEM, keyPEM, err := tls.GetCertificatePEM(getCtx)
			cancel()
			if err != nil {
				return nil, err
			}
			tlsConfigs := []*conf.TLSCertConfig{
				{
					CertStr: []string{string(certPEM)},
					KeyStr:  []string{string(keyPEM)},
				},
			}
			inbound.StreamSetting.TLSSettings.Certs = tlsConfigs
		}
	}
	coreCfg, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return coreCfg, nil
}

type XrayServer struct {
	l   *zap.Logger
	cfg *config.Config

	up       *UserPool
	instance *core.Instance

	mainCtx context.Context
}

var _ common.TunnelServer = (*XrayServer)(nil)

func NewXrayServer(cfg *config.Config) *XrayServer {
	return &XrayServer{l: zap.L().Named("xray"), cfg: cfg}
}

func (xs *XrayServer) Name() string { return "xray" }

func (xs *XrayServer) Setup() error {
	coreCfg, err := buildXrayInstanceCfg(xs.cfg.XRayConfig)
	if err != nil {
		return err
	}
	instance, err := core.New(coreCfg)
	if err != nil {
		return err
	}
	xs.instance = instance

	if xs.cfg.SyncTrafficEndPoint != "" {
		// find api port and server, hard code api Tag to `api`
		grpcEndPoint := xs.cfg.XRayConfig.API.Listen
		var proxyTags []string
		for _, inbound := range xs.cfg.XRayConfig.InboundConfigs {
			if InProxyTags(inbound.Tag) {
				proxyTags = append(proxyTags, inbound.Tag)
			}
		}
		if len(proxyTags) == 0 {
			return errors.New("can't find proxy tag in config")
		}
		xs.up = NewUserPool(grpcEndPoint, xs.cfg.SyncTrafficEndPoint, "", proxyTags)
	}
	return nil
}

func (xs *XrayServer) Stop() {
	xs.l.Warn("Stop Xray Server now...")
	if xs.instance != nil {
		if err := xs.instance.Close(); err != nil {
			xs.l.Error("stop instance meet error", zap.Error(err))
		}
	}

	if xs.up != nil {
		xs.up.Stop()
	}
}

func (xs *XrayServer) Start(ctx context.Context) error {
	xs.l.Info("Start Xray Server now...")
	if err := xs.instance.Start(); err != nil {
		return err
	}

	if xs.up != nil {
		if err := xs.up.Start(ctx); err != nil {
			return err
		}
	}

	if xs.mainCtx == nil {
		xs.mainCtx = ctx
	}
	return nil
}

func (xs *XrayServer) NeedReload(newCfg *config.Config) (bool, error) {
	oldCfgM := make(map[string]conf.InboundDetourConfig)
	for _, inbound := range xs.cfg.XRayConfig.InboundConfigs {
		if InProxyTags(inbound.Tag) {
			oldCfgM[inbound.Tag] = inbound
		}
	}
	for _, newInbound := range newCfg.XRayConfig.InboundConfigs {
		if !InProxyTags(newInbound.Tag) {
			continue
		}
		oldInbound, ok := oldCfgM[newInbound.Tag]
		if !ok {
			xs.l.Info("find new inbound config, need restart instance", zap.String("tag", newInbound.Tag))
			return true, nil
		}
		oldListen := fmt.Sprintf("%s,%s", oldInbound.ListenOn.Address.String(), oldInbound.PortList.Build().String())
		newListen := fmt.Sprintf("%s,%s", newInbound.ListenOn.Address.String(), newInbound.PortList.Build().String())
		xs.l.Debug("check listen port",
			zap.String("old", oldListen), zap.String("new", newListen), zap.String("tag", newInbound.Tag))
		if oldListen != newListen {
			xs.l.Warn("find listener changed reload inbound now...",
				zap.String("old", oldListen),
				zap.String("new", newListen),
				zap.String("tag", newInbound.Tag))
			return true, nil
		}
	}
	return false, nil
}

func (xs *XrayServer) Reload() error {
	xs.l.Warn("Reload Xray Server now...")
	xs.Stop()
	if err := xs.Setup(); err != nil {
		return err
	}
	if err := xs.Start(xs.mainCtx); err != nil {
		return err
	}
	return nil
}
