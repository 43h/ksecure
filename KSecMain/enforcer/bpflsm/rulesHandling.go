// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// Map Key Identifiers for Whitelist/Posture
var (
	PROCWHITELIST = InnerKey{Path: [256]byte{101}}
	FILEWHITELIST = InnerKey{Path: [256]byte{102}}
	NETWHITELIST  = InnerKey{Path: [256]byte{103}}
)

// RuleList Structure contains all the data required to set rules for a particular container
type RuleList struct {
	ProcessRuleList      map[InnerKey][2]uint8
	FileRuleList         map[InnerKey][2]uint8
	NetworkRuleList      map[InnerKey][2]uint8
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
}

var BaitDirDefault = []string{"/"}
var BaitNameStartAndSuffix = [6][2]string{{"/.0", ".db"}, {"/.0", ".js"}, {"/.0", ""}, {"/.租", ".db"}, {"/.租", ".js"}, {"/.租", ""}}

// Init prepares the RuleList object
func (r *RuleList) Init() {
	r.ProcessRuleList = make(map[InnerKey][2]uint8)
	r.ProcWhiteListPosture = false

	r.FileRuleList = make(map[InnerKey][2]uint8)
	r.FileWhiteListPosture = false

	r.NetworkRuleList = make(map[InnerKey][2]uint8)
	r.NetWhiteListPosture = false
}

// UpdateContainerRules updates individual container map with new rules and resolves conflicting rules
func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {

}
