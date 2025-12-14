package main

import (
	"os"

	"github.com/gkirito/st-agent/cli"
)

func main() {
	app := cli.NewApp()
	if err := app.Run(os.Args); err != nil {
		println("ST Agent run error: " + err.Error())
	}
}
