//
//   date  : 2016-02-18
//   author: xjdrew
//

package main

import (
	"flag"
	"fmt"
	"os"

	. "github.com/xjdrew/kone/internal"
	"github.com/xjdrew/kone/k1"
)

var VERSION = "0.1-dev"

func main() {
	version := flag.Bool("version", false, "Get version info")
	debug := flag.Bool("debug", false, "Print debug info")
	config := flag.String("config", "", "config file")
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
	logger.Infof("using config file: %+v", configFile)

	cfg, err := k1.ParseConfig(configFile)
	logger.Debugf("config: %+v", cfg)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	one, err := k1.NewOne(cfg)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	logger.Infof("%v", one.Run())
}
