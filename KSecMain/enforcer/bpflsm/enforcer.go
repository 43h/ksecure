// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor


// Package bpflsm is responsible for setting/cleaning up objects for BPF LSM enforcer and handle updates for the same
package bpflsm

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run -tags lsmbpf github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer_ransomware ../../BPF/enforcer_ransomware.bpf.c -- -I/usr/include/bpf -O2 -g $TARGET_ARCH

// ===================== //
// == BPFLSM Enforcer == //
// ===================== //

// BPFEnforcer structure to maintains relevant objects for BPF LSM Enforcement
type BPFEnforcer struct {
	Logger *fd.Feeder

	ObjRansomWare enforcer_ransomwareObjects

	Probes map[string]link.Link
}

// NewBPFEnforcer instantiates a objects for setting up BPF LSM Enforcement
func NewBPFEnforcer(pinpath string, logger *fd.Feeder) (*BPFEnforcer, error) {

	be := &BPFEnforcer{}

	be.Logger = logger

	if err := rlimit.RemoveMemlock(); err != nil {
		be.Logger.Errf("Error removing rlimit %v", err)
		return nil, nil // Doesn't require clean up so not returning err
	}

	be.Probes = make(map[string]link.Link)

	//attach勒索病毒LSM
	if cfg.GlobalCfg.EnableRansomWareProtect && !attachRansomDetectLSM(pinpath, be) {
		be.Logger.Err("ransom detect LSM attach fail!")
	}

	return be, nil
}

/*
*
挂载勒索病毒诱捕检测程序LSM钩子
*/
func attachRansomDetectLSM(pinpath string, be *BPFEnforcer) bool {
	var err error
	if err = loadEnforcer_ransomwareObjects(&be.ObjRansomWare, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		be.Logger.Errf("error loading BPF LSM objects: %v", err)
		return false
	}

	be.Probes[be.ObjRansomWare.RansomUnlink.String()], err = link.AttachLSM(link.LSMOptions{Program: be.ObjRansomWare.RansomUnlink})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.ObjRansomWare.RansomUnlink.String(), err)
		return false
	}
	
	be.Probes[be.ObjRansomWare.RansomFileOpen.String()], err = link.AttachLSM(link.LSMOptions{Program: be.ObjRansomWare.RansomFileOpen})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.ObjRansomWare.RansomFileOpen.String(), err)
		return false
	}
	
	be.Probes[be.ObjRansomWare.RansomRenameNew.String()], err = link.AttachLSM(link.LSMOptions{Program: be.ObjRansomWare.RansomRenameNew})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.ObjRansomWare.RansomRenameNew.String(), err)
		return false
	}

	be.Probes[be.ObjRansomWare.RansomRenameOld.String()], err = link.AttachLSM(link.LSMOptions{Program: be.ObjRansomWare.RansomRenameOld})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.ObjRansomWare.RansomRenameOld.String(), err)
		return false
	}
	
	return true
}

// UpdateSecurityPolicies loops through containers present in the input endpoint and updates rules for each container
func (be *BPFEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if BPFEnforcer is not active
	if be == nil {
		return
	}

	for _, cid := range endPoint.Containers {
		be.Logger.Printf("Updating container rules for %s", cid)
		be.UpdateContainerRules(cid, endPoint.SecurityPolicies, endPoint.DefaultPosture)
	}

}

// UpdateHostSecurityPolicies updates rules for the host
func (be *BPFEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if BPFEnforcer is not active
	if be == nil {
		return
	}

	be.Logger.Print("Updating host rules")
	be.UpdateHostRules(secPolicies)

}

// DestroyBPFEnforcer cleans up the objects for BPF LSM Enforcer
func (be *BPFEnforcer) DestroyBPFEnforcer() error {
	if be == nil {
		return nil
	}

	errBPFCleanUp := false

	//zhenpeng add
	if err := be.ObjRansomWare.Close(); err != nil {
		be.Logger.Err(err.Error())
		errBPFCleanUp = true
	}

	for _, link := range be.Probes {
		if link == nil {
			continue
		}
		if err := link.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = true
		}
	}

	if errBPFCleanUp {
		return errors.New("error cleaning up BPF LSM Enforcer Objects")
	}

	be = nil
	return nil
}
