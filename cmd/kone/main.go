//
//   date  : 2016-02-18
//   author: xjdrew
//

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xjdrew/kone"
	. "github.com/xjdrew/kone/internal"
)

var VERSION = "0.2-dev"

func main() {
	version := flag.Bool("version", false, "Get version info")
	debug := flag.Bool("debug", false, "Print debug info")
	config := flag.String("config", "config.ini", "config file")
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", VERSION)
		os.Exit(1)
	}

	InitLogger(*debug)
	logger := GetLogger()

	configFile := *config
	if configFile == "" {
		configFile = flag.Arg(0)
	}
	logger.Infof("using config file: %v", configFile)

	cfg, err := kone.ParseConfig(configFile)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	one, err := kone.FromConfig(cfg)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	one.Serve()
}
