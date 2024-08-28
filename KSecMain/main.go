// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package main is the entrypoint to initializing the armor
package main

import (
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"os"
	"path/filepath"
	"regexp"
)

var GitCommit string
var GitBranch string
var BuildDate string

func printBuildDetails() {
	if GitCommit == "" {
		return
	}
	kg.Printf("BUILD-INFO: commit: %v, branch: %v, date: %v",
		GitCommit, GitBranch, BuildDate)
}

func init() {
	printBuildDetails()
}

func main() {

	if os.Geteuid() != 0 {
		kg.Printf("Need to have root privileges to run %s\n", os.Args[0])
		return
	}

	//获取程序运行路径
	exePath, err := os.Executable()
	if err != nil {
		kg.Err(err.Error())
		return
	}

	//验证路径是否包含非法字符
	if match, _ := regexp.MatchString(`[^a-zA-Z0-9_\\\/\.-]`, exePath); match {
		kg.Err("Invalid characters in executable path")
		return
	}

	//切换目录
	if err := os.Chdir(filepath.Dir(exePath)); err != nil {
		kg.Err(err.Error())
		return
	}

	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	core.KubeArmor()

}
