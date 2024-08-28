// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// UpdateHostRules updates host rules map with new rules and resolves conflicting rules
func (be *BPFEnforcer) UpdateHostRules(securityPolicies []tp.HostSecurityPolicy) {
	var hostPolicies []tp.SecurityPolicy

	// Typecast HostSecurityPolicy spec to normal SecurityPolicies
	for _, secPolicy := range securityPolicies {
		var hostPolicy tp.SecurityPolicy
		if err := kl.Clone(secPolicy.Spec.Type, &hostPolicy.Spec.Type); err != nil {
			be.Logger.Warnf("Error cloning host policy spec process to sec policy construct")
		}

		if err := kl.Clone(secPolicy.Spec.Process, &hostPolicy.Spec.Process); err != nil {
			be.Logger.Warnf("Error cloning host policy spec process to sec policy construct")
		}
		if err := kl.Clone(secPolicy.Spec.File, &hostPolicy.Spec.File); err != nil {
			be.Logger.Warnf("Error cloning host policy spec file to sec policy construct")
		}
		if err := kl.Clone(secPolicy.Spec.Network, &hostPolicy.Spec.Network); err != nil {
			be.Logger.Warnf("Error cloning host policy spec network to sec policy construct")
		}

		//add for wannacry
		if err := kl.Clone(secPolicy.Spec.WannaCry, &hostPolicy.Spec.WannaCry); err != nil {
			be.Logger.Warnf("Error cloning host policy spec wannacry to sec policy construct")
		}
		hostPolicies = append(hostPolicies, hostPolicy)
	}
}
