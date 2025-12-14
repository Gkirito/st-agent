package cli

import (
	"os"

	"github.com/gkirito/st-agent/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func loadConfig() (cfg *config.Config, err error) {
	if ConfigPath != "" {
		cfg = config.NewConfig(ConfigPath)
		if err := cfg.LoadConfig(true); err != nil {
			return nil, err
		}
	} else {
		cfg = &config.Config{
			PATH:           ConfigPath,
			LogLevel:       LogLevel,
			ReloadInterval: ConfigReloadInterval,
			// RelayConfigs: []*conf.Config{
			// 	{
			// 		Listen:        LocalAddr,
			// 		ListenType:    ListenType,
			// 		TransportType: TransportType,
			// 	},
			// },
		}
		if err := cfg.Adjust(); err != nil {
			return nil, err
		}
	}

	// init tls when need
	// for _, cfg := range cfg.RelayConfigs {
	// 	if cfg.ListenType == constant.RelayTypeWSS || cfg.ListenType == constant.RelayTypeMWSS ||
	// 		cfg.TransportType == constant.RelayTypeWSS || cfg.TransportType == constant.RelayTypeMWSS {
	// 		if err := tls.InitTlsCfg(); err != nil {
	// 			return nil, err
	// 		}
	// 		break
	// 	}
	// }
	return cfg, nil
}

func initLogger(cfg *config.Config) error {
	level := zapcore.InfoLevel
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return err
	}
	writers := []zapcore.WriteSyncer{zapcore.AddSync(os.Stderr)}
	encoder := zapcore.EncoderConfig{
		TimeKey:     "ts",
		LevelKey:    "level",
		MessageKey:  "msg",
		NameKey:     "name",
		EncodeLevel: zapcore.LowercaseColorLevelEncoder,
		EncodeTime:  zapcore.RFC3339TimeEncoder,
		EncodeName:  zapcore.FullNameEncoder,
	}
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoder),
		zapcore.NewMultiWriteSyncer(writers...),
		level,
	)
	l := zap.New(core)
	zap.ReplaceGlobals(l)
	return nil
}
