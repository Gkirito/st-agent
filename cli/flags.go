package cli

import (
	cli "github.com/urfave/cli/v2"
)

var (
	ConfigPath           string
	SystemFilePath       = "/etc/systemd/system/stagent.service"
	LogLevel             string
	ConfigReloadInterval int
)

var RootFlags = []cli.Flag{
	&cli.StringFlag{
		Name:        "config",
		Usage:       "配置文件地址，支持文件类型或 http api",
		Aliases:     []string{"c"},
		EnvVars:     []string{"STAGENT_CONFIG_FILE"},
		Destination: &ConfigPath,
	},
	&cli.StringFlag{
		Name:        "log_level",
		Usage:       "log level",
		Aliases:     []string{"ll"},
		EnvVars:     []string{"STAGENT_LOG_LEVEL"},
		Destination: &LogLevel,
		DefaultText: "info",
	},
	&cli.IntFlag{
		Name:        "config_reload_interval",
		Usage:       "config reload interval",
		EnvVars:     []string{"STAGENT_CONFIG_RELOAD_INTERVAL"},
		Aliases:     []string{"cri"},
		Destination: &ConfigReloadInterval,
		DefaultText: "60",
	},
}

func NewApp() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		// println("Welcome to safetunnel agent (st-agent is a network relay tool and a typo)")
		// println(fmt.Sprintf("Version=%s", constant.Version))
		// println(fmt.Sprintf("GitBranch=%s", constant.GitBranch))
		// println(fmt.Sprintf("GitRevision=%s", constant.GitRevision))
		// println(fmt.Sprintf("BuildTime=%s", constant.BuildTime))
	}
	app := cli.NewApp()
	app.Name = "st-agent"
	app.Flags = RootFlags
	// app.Version = constant.Version
	app.Commands = []*cli.Command{InstallCMD}
	app.Usage = "st-agent is a network relay tool and a typo :)"
	app.Action = action
	return app
}
