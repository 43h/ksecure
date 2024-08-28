// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	"fmt"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	be "github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	md "github.com/kubearmor/KubeArmor/KubeArmor/module"
	"os"
	"path/filepath"
	"strings"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string

	// LSM - BPFLSM
	BpfEnforcer *be.BPFEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(pinpath string, logger *fd.Feeder) *RuntimeEnforcer {
	var err error
	re := &RuntimeEnforcer{}
	re.Logger = logger

	// mount securityfs
	if err := kl.RunCommandAndWaitWithErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"}); err != nil {
		if _, err := os.Stat(filepath.Clean("/sys/kernel/security")); err != nil {
			re.Logger.Errf("Failed to read /sys/kernel/security (%s)", err.Error())
			return nil
		}
	}

	//bpf-lsm 支持确认
	lsm := []byte{}
	lsmPath := "/sys/kernel/security/lsm"
	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = os.ReadFile(lsmPath)
		if err != nil {
			re.Logger.Errf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
			return nil
		}
	}
	if !kl.ContainsElement(strings.Split(string(lsm), ","), "bpf") {
		re.Logger.Printf("Supported LSMs: %s,not Support BPF-LSM", string(lsm))
		return nil
	}

	// 初始化安全加固模块
	md.ModuleMapLock.Lock()
	md.ModuleObjectMap[kl.RansomModule] = md.NewRansomwareModule()
	md.ModuleMapLock.Unlock()

	//初始化BPF挂载
	re.BpfEnforcer, err = be.NewBPFEnforcer(pinpath, logger)
	if re.BpfEnforcer != nil {
		if err != nil {
			re.Logger.Print("Error Initialising BPF-LSM Enforcer, Cleaning Up")
			if err := re.BpfEnforcer.DestroyBPFEnforcer(); err != nil {
				re.Logger.Err(err.Error())
			} else {
				re.Logger.Print("Destroyed BPF-LSM Enforcer")
			}
		}
		re.Logger.Print("Initialized BPF-LSM Enforcer")
		re.EnforcerType = "BPFLSM"
		logger.UpdateEnforcer(re.EnforcerType)

		//开启日志接收
		if cfg.GlobalCfg.EnableRansomWareProtect {
			go md.ModuleObjectMap[kl.RansomModule].ReceiveLog(re.BpfEnforcer.ObjRansomWare.RbRansomware, re.BpfEnforcer, re.Logger)
		}

		return re
	}

	re.Logger.Err("Initialized BPF-LSM Enforcer Error")
	return nil
}

// UpdateHostSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateHostSecurityPolicies(module string, policies []interface{}) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		// skip if BPFEnforcer is not active
		if re.BpfEnforcer == nil {
			re.BpfEnforcer.Logger.Print("Updating host rules")
			return
		}

		re.BpfEnforcer.Logger.Printf("Updating host rules:%s", module)

		id := "host"
		moduleObject := md.ModuleObjectMap[module]
		if moduleObject != nil {
			moduleObject.UpdateRules(id, policies, re.BpfEnforcer)
		}

	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	// skip if runtime enforcer is not active
	if re == nil {
		return nil
	}

	errorLSM := false

	if re.EnforcerType == "BPFLSM" {
		if re.BpfEnforcer != nil {
			if err := re.BpfEnforcer.DestroyBPFEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed BPF-LSM Enforcer")
			}
		}
	}

	if errorLSM {
		return fmt.Errorf("failed to destroy RuntimeEnforcer (%s)", re.EnforcerType)
	}

	// Reset Enforcer to nil if no errors during clean up
	re = nil
	return nil
}
