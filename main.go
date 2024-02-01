package main

import (
	"github.com/m-1tZ/dnstake2/internal/option"
	"github.com/m-1tZ/dnstake2/internal/runner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func init() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
}

func main() {
	opt := option.Parse()

	if opt.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if err := runner.New(opt); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}
