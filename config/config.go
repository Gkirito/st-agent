package config

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	httputil "github.com/gkirito/st-agent/tool/http_util"
	"github.com/gkirito/st-agent/tunnel/anytls"
	"github.com/gkirito/st-agent/tunnel/hysteria"

	xConf "github.com/xtls/xray-core/infra/conf"
	"go.uber.org/zap"
)

type Config struct {
	PATH string

	LogLevel       string `json:"log_level,omitempty"`
	ReloadInterval int    `json:"reload_interval,omitempty"`

	// RelayConfigs      []*conf.Config `json:"relay_configs"`
	// RelaySyncURL      string         `json:"relay_sync_url,omitempty"`
	// RelaySyncInterval int            `json:"relay_sync_interval,omitempty"`

	XRayConfig          *xConf.Config          `json:"xray_config,omitempty"`
	HysteriaConfig      *hysteria.ServerConfig `json:"hysteria_config,omitempty"`
	AnytlsConfig        *anytls.ServerConfig   `json:"anytls_config,omitempty"`
	SyncTrafficEndPoint string                 `json:"sync_traffic_endpoint,omitempty"`

	lastLoadTime time.Time
	l            *zap.SugaredLogger
}

func NewConfig(path string) *Config {
	return &Config{PATH: path, l: zap.S().Named("cfg")}
}

func (c *Config) NeedSyncFromServer() bool {
	return strings.Contains(c.PATH, "http")
}

func (c *Config) LoadConfig(force bool) error {
	if c.ReloadInterval > 0 && time.Since(c.lastLoadTime).Seconds() < float64(c.ReloadInterval) && !force {
		c.l.Warnf("Skip Load Config, last load time: %s", c.lastLoadTime)
		return nil
	}
	// reset
	// c.RelayConfigs = nil
	c.lastLoadTime = time.Now()
	if c.NeedSyncFromServer() {
		if err := c.readFromHttp(); err != nil {
			return err
		}
	} else {
		if err := c.readFromFile(); err != nil {
			return err
		}
	}
	return c.Adjust()
}

func (c *Config) readFromFile() error {
	file, err := os.ReadFile(c.PATH)
	if err != nil {
		return err
	}
	c.l.Infof("Load Config From File: %s", c.PATH)
	return json.Unmarshal([]byte(file), &c)
}

func (c *Config) readFromHttp() error {
	c.l.Infof("Load Config From HTTP: %s", c.PATH)
	if newC, err := httputil.JsonReq[Config](context.TODO(), http.MethodGet, c.PATH, nil, nil, nil); err != nil {
		return err
	} else {
		*c = newC
	}
	return nil
}

func (c *Config) Adjust() error {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	// for _, r := range c.RelayConfigs {
	// 	if err := r.Validate(); err != nil {
	// 		return err
	// 	}
	// }

	// check relay config label is unique
	// labelMap := make(map[string]struct{})
	// for _, r := range c.RelayConfigs {
	// 	if _, ok := labelMap[r.Label]; ok {
	// 		return fmt.Errorf("relay label %s is not unique", r.Label)
	// 	}
	// 	labelMap[r.Label] = struct{}{}
	// }
	return nil
}

func (c *Config) NeedStartXrayServer() bool {
	return c.XRayConfig != nil
}

func (c *Config) NeedStartHysteriaServer() bool {
	return c.HysteriaConfig != nil
}

func (c *Config) NeedStartAnytlsServer() bool {
	return c.AnytlsConfig != nil
}
