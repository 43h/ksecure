// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"github.com/cilium/ebpf"
)

// ContainerKV contains Keys for individual container eBPF Map and the Map itself
type ContainerKV struct {
	Key   OuterKeyForFile
	Map   *ebpf.Map
	Rules RuleList
}

type InnerMapKV struct {
	Map *ebpf.Map
}

// NsKey Structure acts as an Identifier for containers
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// InnerKey Structure Rule Identifier
type InnerKey struct {
	Path   [256]byte //客体路径
	Source [256]byte //主体路径
}

type InnerValue struct {
	VER     uint32
	DEFENSE uint8
	FILE    uint8
}

// OuterKeyForFile Structure contains Map Rule Identifier
type OuterKeyForFile struct {
	Path [256]byte
}

// InnerKey Structure contains Map Rule Identifier
type WannacryKey struct {
	Path [256]byte
}
