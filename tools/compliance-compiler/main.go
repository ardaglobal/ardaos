package main

import (
	"fmt"
	"os"

	"github.com/arda-org/arda-os/tools/compliance-compiler/cmd"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

var rootCmd = &cobra.Command{
	Use:   "compliance-compiler",
	Short: "ArdaOS Compliance Policy Compiler",
	Long: `compliance-compiler is a standalone tool for compiling YAML compliance policies
into protobuf format for use with ArdaOS blockchain compliance modules.

It provides commands to compile, validate, test, and generate compliance policies
with support for regional regulatory requirements and custom business rules.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initializeLogging()
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is $HOME/.compliance-compiler.yaml)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringP("log-format", "f", "text", "log format (text, json)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	rootCmd.AddCommand(cmd.NewCompileCmd())
	rootCmd.AddCommand(cmd.NewValidateCmd())
	rootCmd.AddCommand(cmd.NewTestCmd())
	rootCmd.AddCommand(cmd.NewGenerateCmd())
	rootCmd.AddCommand(cmd.NewDebugCmd())
}

func initConfig() {
	if cfgFile := viper.GetString("config"); cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			logrus.Fatal(err)
		}

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".compliance-compiler")
	}

	viper.SetEnvPrefix("COMPLIANCE_COMPILER")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		logrus.Debug("Using config file:", viper.ConfigFileUsed())
	}
}

func initializeLogging() {
	level, err := logrus.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		logrus.Fatal("Invalid log level:", err)
	}
	logrus.SetLevel(level)

	if viper.GetString("log.format") == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	if viper.GetBool("verbose") {
		logrus.SetLevel(logrus.DebugLevel)
	}
}
