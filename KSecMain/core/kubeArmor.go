// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	efc "github.com/kubearmor/KubeArmor/KubeArmor/enforcer"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ====================== //
// == KubeArmor Daemon == //
// ====================== //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// KubeArmorDaemon Structure
type KubeArmorDaemon struct {
	// node
	Node     tp.Node
	NodeLock *sync.RWMutex

	// flag
	K8sEnabled bool

	// K8s pods (from kubernetes)
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.RWMutex

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

	// endpoints
	EndPoints     []tp.EndPoint
	EndPointsLock *sync.RWMutex

	// Security policies
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// Host Security policies
	HostSecurityPolicies     []tp.HostSecurityPolicy
	HostSecurityPoliciesLock *sync.RWMutex

	// Host Security policyMap-key:module,value:module-host-policy
	HostSecurityPolicyMap     map[string][]interface{}
	HostSecurityPolicyMapLock *sync.RWMutex

	//DefaultPosture (namespace -> postures)
	DefaultPostures     map[string]tp.DefaultPosture
	DefaultPosturesLock *sync.Mutex

	// pid map
	ActiveHostPidMap map[string]tp.PidMap
	ActivePidMapLock *sync.RWMutex

	// logger
	Logger *fd.Feeder

	// runtime enforcer
	RuntimeEnforcer *efc.RuntimeEnforcer

	// WgDaemon Handler
	WgDaemon sync.WaitGroup

	// system monitor lock
	MonitorLock *sync.RWMutex
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon() *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	dm.Node = tp.Node{}
	dm.NodeLock = new(sync.RWMutex)

	dm.K8sEnabled = false

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = new(sync.RWMutex)

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)
	dm.EndPoints = []tp.EndPoint{}
	dm.EndPointsLock = new(sync.RWMutex)

	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)

	dm.HostSecurityPolicies = []tp.HostSecurityPolicy{}
	dm.HostSecurityPoliciesLock = new(sync.RWMutex)

	dm.HostSecurityPolicyMap = map[string][]interface{}{}
	dm.HostSecurityPolicyMapLock = new(sync.RWMutex)

	dm.DefaultPostures = map[string]tp.DefaultPosture{}
	dm.DefaultPosturesLock = new(sync.Mutex)

	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = new(sync.RWMutex)

	dm.Logger = nil
	dm.RuntimeEnforcer = nil

	dm.WgDaemon = sync.WaitGroup{}

	dm.MonitorLock = new(sync.RWMutex)

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KubeArmorDaemon) DestroyKubeArmorDaemon() {
	if dm.RuntimeEnforcer != nil {
		// close runtime enforcer
		if dm.CloseRuntimeEnforcer() {
			dm.Logger.Print("Stopped KSec Enforcer")
		}
	}

	if dm.Logger != nil {
		dm.Logger.Print("Terminated KSec")
	} else {
		kg.Print("Terminated KSec")
	}

	// wait for a while
	time.Sleep(time.Second * 1)

	if dm.Logger != nil {
		// close logger
		if dm.CloseLogger() {
			kg.Print("Stopped KSec Logger")
		}
	}

	// wait for other routines
	kg.Print("Waiting for routine terminations")
	dm.WgDaemon.Wait()

	// delete pid file
	if _, err := os.Stat(cfg.PIDFilePath); err == nil {
		kg.Print("Deleting PID file")

		err := os.Remove(cfg.PIDFilePath)
		if err != nil {
			kg.Errf("Failed to delete PID file")
		}
	}
}

// ============ //
// == Logger == //
// ============ //

// InitLogger Function
func (dm *KubeArmorDaemon) InitLogger() bool {
	dm.Logger = fd.NewFeeder(&dm.Node, &dm.NodeLock)
	return dm.Logger != nil
}

// ServeLogFeeds Function
func (dm *KubeArmorDaemon) ServeLogFeeds() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.Logger.ServeLogFeeds()
}

// CloseLogger Function
func (dm *KubeArmorDaemon) CloseLogger() bool {
	if err := dm.Logger.DestroyFeeder(); err != nil {
		kg.Errf("Failed to destroy KubeArmor Logger (%s)", err.Error())
		return false
	}
	return true
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer(pinpath string) bool {
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(pinpath, dm.Logger)
	return dm.RuntimeEnforcer != nil
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() bool {
	if err := dm.RuntimeEnforcer.DestroyRuntimeEnforcer(); err != nil {
		dm.Logger.Errf("Failed to destory KubeArmor Enforcer (%s)", err.Error())
		return false
	}
	return true
}

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// ========== //
// == Main == //
// ========== //

// KubeArmor Function
func KubeArmor() {
	// create a daemon
	dm := NewKubeArmorDaemon()

	// 系统信息获取
	dm.NodeLock.Lock()
	dm.Node.NodeName = cfg.GlobalCfg.Host
	dm.Node.NodeIP = kl.GetExternalIPAddr()

	dm.Node.Annotations = map[string]string{}
	dm.HandleNodeAnnotations(&dm.Node)

	hostInfo := kl.GetCommandOutputWithoutErr("hostnamectl", []string{})
	for _, line := range strings.Split(hostInfo, "\n") {
		if strings.Contains(line, "Operating System") {
			dm.Node.OSImage = strings.Split(line, ": ")[1]
			break
		}
	}

	dm.Node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	dm.Node.KernelVersion = strings.TrimSuffix(dm.Node.KernelVersion, "\n")
	dm.NodeLock.Unlock()

	dm.NodeLock.RLock()
	kg.Printf("Host Name: %s", dm.Node.NodeName)
	kg.Printf("OS Image: %s", dm.Node.OSImage)
	kg.Printf("Kernel Version: %s", dm.Node.KernelVersion)
	dm.NodeLock.RUnlock()

	// == //
	// 初始化日志处理模块
	if !dm.InitLogger() {
		kg.Err("Failed to intialize KSec Logger")
		// destroy the daemon
		dm.DestroyKubeArmorDaemon()
		return
	}
	dm.Logger.Print("Initialized KSec Logger")

	// == //
	// 开启运行时增强防御
	if !dm.InitRuntimeEnforcer(kl.GetMapRoot()) {
		dm.Logger.Print("Disabled KSec Enforcer since No LSM is enabled")
	} else {
		dm.Logger.Print("Initialized KSec Enforcer")
		dm.Logger.Print("Started to protect a host")
	}
	// == //
	// wait for a while
	time.Sleep(time.Second * 1)

	//开启日志监控
	// serve log feeds
	go dm.ServeLogFeeds()
	dm.Logger.Print("Started to serve log feeds")

	// == //
	// initialized KSec
	dm.Logger.Print("Initialized KSec")

	// == //
	//加载安全策略
	dm.loadKubeArmorHostPolicies()

	// == //
	//监控组件关闭信号
	if !cfg.GlobalCfg.CoverageTest {
		// listen for interrupt signals
		sigChan := GetOSSigChannel()
		<-sigChan
		dm.Logger.Print("Got a signal to terminate KSec")
		close(StopChan)
	}

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}
