package cmd

import (
	"context"
	"os"

	"github.com/esiddiqui/goidc-proxy/config"
	"github.com/esiddiqui/goidc-proxy/oidc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type RootOpts struct {
	ConfigPath string
	LoggerMode string
}

func Exec() {
	ctx := context.Background() // for now
	cmd := getRootCommand()
	err := cmd.ExecuteContext(ctx)
	if err != nil {
		log.Error(err)
		os.Exit(-1)
	}
}

func getRootCommand() *cobra.Command {

	opts := &RootOpts{}
	version := "0.01"
	rootCmd := &cobra.Command{
		Use:           "goidc-proxy",
		Version:       version,
		Short:         "goidc-proxy runs a light-weight reverse-proxy & negotiates oidc flow for upstream apps",
		SilenceErrors: true, // cobra prints errors returned from RunE by default. Disable that since we handle errors ourselves.
		SilenceUsage:  true, // cobra prints command usage by default if RunE returns an error.
		Run:           getRun(opts),
	}

	persistentFlags := rootCmd.PersistentFlags()
	persistentFlags.StringVar(&opts.ConfigPath, "config", "proxy.yml", "The fully-qualified filename for goidc-proxy configuration")
	persistentFlags.StringVar(&opts.LoggerMode, "log-level", "info", "Set the logger break-level (fatal | error| warn| info| debug|trace)")

	return rootCmd
}

// getRun returns the run function that acutall does the work
func getRun(opts *RootOpts) func(*cobra.Command, []string) {
	return func(c *cobra.Command, s []string) {
		// intialize logger
		configureLogger(opts.LoggerMode)

		// load config
		log.Debug("loading goidc-proxy configuration")
		cfg := config.LoadConfig(opts.ConfigPath)

		// start goidc proxy server
		_, err := oidc.NewGoidcProxyServer(cfg)
		if err != nil {
			panic(err)
		}
	}
}

// configures the logger to the supplied level
func configureLogger(level string) {

	var logLevel log.Level

	switch level {
	case "trace":
		logLevel = log.TraceLevel
	case "debug":
		logLevel = log.DebugLevel
	case "info":
		logLevel = log.InfoLevel
	case "warn":
		logLevel = log.WarnLevel
	case "error":
		logLevel = log.ErrorLevel
	case "fatal":
		logLevel = log.FatalLevel
	case "panic":
		logLevel = log.PanicLevel
	default:
		logLevel = log.InfoLevel
	}

	//set log level & formatter..
	log.SetLevel(logLevel)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
	})
	log.Debugf("log level set to %v", level)
}
