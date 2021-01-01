/*
Copyright © 2019 Charlie Belmer <Charlie.Belmer@protonmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string
var target string
var request string
var proxy string
var userAgent string
var requestData string
var requireHTTPS bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nosqli",
	Short: "A NoSQL Injection and test CLI application",
	Long: `NoSQLInjector is a CLI tool for testing Datastores that 
do not depend on SQL as a query language. 

nosqli aims to be a simple automation tool for identifying and exploiting 
NoSQL Injection vectors.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nosqli.yaml)")
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "target url eg. http://site.com/page?arg=1")
	rootCmd.PersistentFlags().StringVarP(&request, "request", "r", "", "Load in a request from a file, such as a request generated in Burp or ZAP.")
	rootCmd.PersistentFlags().StringVarP(&proxy, "proxy", "p", "", "Proxy requests through this proxy URL. Defaults to HTTP_PROXY environment variable.")
	rootCmd.PersistentFlags().StringVarP(&userAgent, "user-agent", "u", "", "Specify a user agent")
	rootCmd.PersistentFlags().StringVarP(&requestData, "data", "d", "", "Specify default post data (should not include any injection strings)")
	rootCmd.PersistentFlags().BoolVar(&requireHTTPS, "https", false, "Always send requests as HTTPS (Defaults to HTTP when using request files)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".nosqli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".nosqli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
