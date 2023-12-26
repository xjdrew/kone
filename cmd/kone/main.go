//
//   date  : 2016-02-18
//   author: xjdrew
//

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/op/go-logging"
	"github.com/xjdrew/kone"
)

var VERSION = "0.3-dev"

var logger = logging.MustGetLogger("kone")

func init() {
	logging.SetFormatter(logging.MustStringFormatter(
		`%{color}%{time:06-01-02 15:04:05.000} %{level:.4s} @%{shortfile}%{color:reset} %{message}`,
	))
	logging.SetBackend(logging.NewLogBackend(os.Stdout, "", 0))
}

func main() {
	version := flag.Bool("version", false, "Get version info")
	debug := flag.Bool("debug", false, "Print debug info")
	config := flag.String("config", "config.ini", "config file")
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", VERSION)
		os.Exit(1)
	}

	if *debug {
		logging.SetLevel(logging.DEBUG, "kone")
	} else {
		logging.SetLevel(logging.INFO, "kone")
	}

	configFile := *config
	if configFile == "" {
		configFile = flag.Arg(0)
	}
	logger.Infof("using config file: %v", configFile)

	cfg, err := kone.ParseConfig(configFile)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(2)
	}

	one, err := kone.FromConfig(cfg)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(3)
	}
	one.Serve()
}
