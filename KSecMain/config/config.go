// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package config is the component responsible for loading KubeArmor configurations
package config

import (
	"fmt"
	"os"
	"strings"

	"flag"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/spf13/viper"
)

// KubearmorConfig Structure
type KubearmorConfig struct {
	//Cluster string // Cluster name to use for feeds
	Host string // Host name to use for feeds

	LogPath string // Log file to use

	HostPolicy bool // Enable/Disable host policy enforcement

	CoverageTest bool // Enable/Disable Coverage Test

	EnableRansomWareProtect bool   //ransom
	YamlPath                string // Log file to use
}

// PolicyDir policy dir path for host policies backup
const PolicyDir string = "/opt/KSec/policy/.cache/"

// PIDFilePath for pid file path
const PIDFilePath string = "/opt/KSec/KSec.pid"

// GlobalCfg Global configuration for Kubearmor
var GlobalCfg KubearmorConfig

// ConfigHost Host name key
const ConfigHost string = "host"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

const YamlPath string = "yamlPath"

// ConfigHostVisibility Host visibility key
const ConfigHostVisibility string = "hostVisibility"

// ConfigKubearmorHostPolicy Kubearmor host policy key
const ConfigKubearmorHostPolicy string = "enableHostPolicy"

// ConfigCoverageTest Coverage Test key
const ConfigCoverageTest string = "coverageTest"

// Ransom
const RansomSwitch string = "ransom"

func readCmdLineParams() {
	hostname, _ := os.Hostname()
	hostStr := flag.String(ConfigHost, strings.Split(hostname, ".")[0], "host name")

	logStr := flag.String(ConfigLogPath, "none", "log file path, {path|stdout|none}")

	hostVisStr := flag.String(ConfigHostVisibility, "default", "Host Visibility to use [process,file,network,capabilities,none] (default \"none\" for k8s, \"process,file,network,capabilities\" for VM)")

	hostPolicyB := flag.Bool(ConfigKubearmorHostPolicy, false, "enabling KubeArmorHostPolicy")

	coverageTestB := flag.Bool(ConfigCoverageTest, false, "enabling CoverageTest")

	yamlStr := flag.String(YamlPath, "", "log file path, {path}")

	ransomSwitch := flag.String(RansomSwitch, "on", "ransom feature setting")

	flags := []string{}
	flag.VisitAll(func(f *flag.Flag) {
		kv := fmt.Sprintf("%s:%v", f.Name, f.Value)
		flags = append(flags, kv)
	})
	kg.Printf("Arguments [%s]", strings.Join(flags, " "))

	flag.Parse()

	viper.SetDefault(ConfigHost, *hostStr)

	viper.SetDefault(ConfigLogPath, *logStr)

	viper.SetDefault(ConfigHostVisibility, *hostVisStr)

	viper.SetDefault(ConfigKubearmorHostPolicy, *hostPolicyB)

	viper.SetDefault(ConfigCoverageTest, *coverageTestB)

	viper.SetDefault(YamlPath, *yamlStr)

	viper.SetDefault(RansomSwitch, *ransomSwitch)
}

// LoadConfig Load configuration
func LoadConfig() error {
	// Read configuration from command line
	readCmdLineParams()

	// Read configuration from env var
	// Note that the env var has to be set in uppercase for e.g, CLUSTER=xyz ./kubearmor
	viper.AutomaticEnv()

	// Read configuration from config file
	cfgfile := os.Getenv("KSEC_CFG")
	if cfgfile == "" {
		cfgfile = "KSec.yaml"
	}
	if _, err := os.Stat(cfgfile); err == nil {
		kg.Printf("setting config from file [%s]", cfgfile)
		viper.SetConfigFile(cfgfile)
		err := viper.ReadInConfig()
		if err != nil {
			return err
		}
	}

	GlobalCfg.Host = viper.GetString(ConfigHost)

	GlobalCfg.LogPath = viper.GetString(ConfigLogPath)

	GlobalCfg.HostPolicy = viper.GetBool(ConfigKubearmorHostPolicy)

	GlobalCfg.HostPolicy = true

	GlobalCfg.CoverageTest = viper.GetBool(ConfigCoverageTest)

	GlobalCfg.YamlPath = viper.GetString(YamlPath)

	GlobalCfg.EnableRansomWareProtect = true

	kg.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
