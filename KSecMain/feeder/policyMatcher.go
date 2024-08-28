// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ======================= //
// == Security Policies == //
// ======================= //

// getProtocolFromName Function
func getProtocolFromName(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp":
		return "protocol=TCP,type=SOCK_STREAM"
	case "udp":
		return "protocol=UDP,type=SOCK_DGRAM"
	case "icmp":
		return "protocol=ICMP,type=SOCK_RAW"
	case "raw":
		return "type=SOCK_RAW"
	default:
		return "unknown"
	}
}

func getFileProcessUID(path string) string {
	info, err := os.Stat(path)
	if err == nil {
		stat := info.Sys().(*syscall.Stat_t)
		uid := stat.Uid

		return strconv.Itoa(int(uid))
	}

	return ""
}

// getOperationAndCapabilityFromName Function
func getOperationAndCapabilityFromName(capName string) (op, cap string) {
	switch strings.ToLower(capName) {
	case "net_raw":
		op = "Network"
		cap = "SOCK_RAW"
	default:
		return "", "unknown"
	}

	return op, cap
}

// newMatchPolicy Function
func (fd *Feeder) newMatchPolicy(policyEnabled int, policyName, src string, mp interface{}) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Source:     src,
	}

	if ppt, ok := mp.(tp.ProcessPathType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Path
		match.ResourceType = "Path"

		match.OwnerOnly = ppt.OwnerOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Allow" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Block" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if pdt, ok := mp.(tp.ProcessDirectoryType); ok {
		match.Severity = strconv.Itoa(pdt.Severity)
		match.Tags = pdt.Tags
		match.Message = pdt.Message

		match.Operation = "Process"
		match.Resource = pdt.Directory
		match.ResourceType = "Directory"

		match.OwnerOnly = pdt.OwnerOnly
		match.Recursive = pdt.Recursive

		if policyEnabled == tp.KubeArmorPolicyAudited && pdt.Action == "Allow" {
			match.Action = "Audit (" + pdt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && pdt.Action == "Block" {
			match.Action = "Audit (" + pdt.Action + ")"
		} else {
			match.Action = pdt.Action
		}
	} else if ppt, ok := mp.(tp.ProcessPatternType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Pattern
		match.ResourceType = "" // to be defined based on the pattern matching syntax

		match.OwnerOnly = ppt.OwnerOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Allow" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Block" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if fpt, ok := mp.(tp.FilePathType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message

		match.Operation = "File"
		match.Resource = fpt.Path
		match.ResourceType = "Path"

		if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Allow" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Block" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if wct, ok := mp.(tp.WannaCryDirType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = nil
		match.Message = "wct.Message"

		match.Operation = "WannaCry"
		match.Resource = ""
		match.ResourceType = "Path"

		match.OwnerOnly = false
		match.ReadOnly = true

		match.Action = "Audit (Block)"
		if len(wct.Dir) == 0 {
			println("hello world")
		}

	} else if fdt, ok := mp.(tp.FileDirectoryType); ok {
		match.Severity = strconv.Itoa(fdt.Severity)
		match.Tags = fdt.Tags
		match.Message = fdt.Message

		match.Operation = "File"
		match.Resource = fdt.Directory
		match.ResourceType = "Directory"

		match.OwnerOnly = fdt.OwnerOnly
		match.ReadOnly = fdt.ReadOnly
		match.Recursive = fdt.Recursive

		if policyEnabled == tp.KubeArmorPolicyAudited && fdt.Action == "Allow" {
			match.Action = "Audit (" + fdt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fdt.Action == "Block" {
			match.Action = "Audit (" + fdt.Action + ")"
		} else {
			match.Action = fdt.Action
		}
	} else if fpt, ok := mp.(tp.FilePatternType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message
		match.Operation = "File"
		match.Resource = fpt.Pattern
		match.ResourceType = "" // to be defined based on the pattern matching syntax

		match.OwnerOnly = fpt.OwnerOnly
		match.ReadOnly = fpt.ReadOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Allow" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Block" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if npt, ok := mp.(tp.NetworkProtocolType); ok {
		match.Severity = strconv.Itoa(npt.Severity)
		match.Tags = npt.Tags
		match.Message = npt.Message

		match.Operation = "Network"
		match.Resource = getProtocolFromName(npt.Protocol)
		match.ResourceType = "Protocol"

		if policyEnabled == tp.KubeArmorPolicyAudited && npt.Action == "Allow" {
			match.Action = "Audit (" + npt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && npt.Action == "Block" {
			match.Action = "Audit (" + npt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyEnabled && fd.IsGKE && npt.Action == "Block" {
			match.Action = "Audit (" + npt.Action + ")"
		} else {
			match.Action = npt.Action
		}
	} else if cct, ok := mp.(tp.CapabilitiesCapabilityType); ok {
		match.Severity = strconv.Itoa(cct.Severity)
		match.Tags = cct.Tags
		match.Message = cct.Message

		op, cap := getOperationAndCapabilityFromName(cct.Capability)

		match.Operation = op
		match.Resource = cap
		match.ResourceType = "Capability"

		if policyEnabled == tp.KubeArmorPolicyAudited && cct.Action == "Allow" {
			match.Action = "Audit (" + cct.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && cct.Action == "Block" {
			match.Action = "Audit (" + cct.Action + ")"
		} else {
			match.Action = cct.Action
		}
	} else if smt, ok := mp.(tp.SyscallMatchType); ok {
		match.Severity = strconv.Itoa(smt.Severity)
		match.Tags = smt.Tags
		match.Message = smt.Message
		match.Operation = "Syscall"
		match.ResourceType = strings.ToUpper(smt.Syscalls[0])
		match.Action = "Audit"
	} else if smpt, ok := mp.(tp.SyscallMatchPathType); ok {
		match.Severity = strconv.Itoa(smpt.Severity)
		match.Tags = smpt.Tags
		match.Message = smpt.Message
		match.Action = "Audit"
		match.Operation = "Syscall"
		match.Resource = smpt.Path
		match.ResourceType = strings.ToUpper(smpt.Syscalls[0])

	} else {
		return tp.MatchPolicy{}
	}

	return match
}

// UpdateSecurityPolicies Function
func (fd *Feeder) UpdateSecurityPolicies(action string, endPoint tp.EndPoint) {
	name := endPoint.NamespaceName + "_" + endPoint.EndPointName

	if action == "DELETED" {
		delete(fd.SecurityPolicies, name)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range endPoint.SecurityPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}

		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.Capability) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		// MatchSyscalls
		for _, syscallRule := range secPolicy.Spec.Syscalls.MatchSyscalls {
			if len(syscallRule.Syscalls) == 0 {
				continue
			}
			fromSource := ""
			syscall := tp.SyscallMatchType{
				Tags:     syscallRule.Tags,
				Message:  syscallRule.Message,
				Severity: syscallRule.Severity,
			}
			if len(syscallRule.FromSource) == 0 {
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 {
						continue
					}
					matches.Policies = append(matches.Policies, match)
				}
				continue
			}

			for _, src := range syscallRule.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Dir) > 0 {
					fromSource = src.Dir
					if !strings.HasSuffix(fromSource, "/") {
						fromSource += "/"
					}
				} else {
					continue
				}
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 {
						continue
					}
					match.IsFromSource = len(fromSource) > 0
					match.Recursive = len(src.Path) == 0 && src.Recursive
					matches.Policies = append(matches.Policies, match)
				}

			}
		}
		// SyscallsMatchPath
		for _, syscallRule := range secPolicy.Spec.Syscalls.MatchPaths {
			if len(syscallRule.Path) == 0 || len(syscallRule.Syscalls) == 0 {
				continue
			}
			fromSource := ""
			syscall := tp.SyscallMatchPathType{
				Tags:     syscallRule.Tags,
				Message:  syscallRule.Message,
				Severity: syscallRule.Severity,
				Path:     syscallRule.Path,
			}
			if len(syscallRule.FromSource) == 0 {
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 && len(match.Resource) == 0 {
						continue
					}
					match.ReadOnly = syscallRule.Recursive
					matches.Policies = append(matches.Policies, match)
				}
				continue
			}

			for _, src := range syscallRule.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Dir) > 0 {
					fromSource = src.Dir
					if !strings.HasSuffix(fromSource, "/") {
						fromSource += "/"
					}
				} else {
					continue
				}
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 && len(match.Resource) == 0 {
						continue
					}
					match.IsFromSource = len(fromSource) > 0
					match.Recursive = len(src.Path) == 0 && src.Recursive
					match.ReadOnly = syscallRule.Recursive
					matches.Policies = append(matches.Policies, match)
				}
			}

		}
	}

	fd.SecurityPoliciesLock.Lock()
	fd.SecurityPolicies[name] = matches
	fd.SecurityPoliciesLock.Unlock()
}

// ============================ //
// == Host Security Policies == //
// ============================ //

// UpdateHostSecurityPolicies Function
func (fd *Feeder) UpdateHostSecurityPolicies(action string, secPolicies []tp.HostSecurityPolicy) {
	if action == "DELETED" {
		delete(fd.SecurityPolicies, fd.Node.NodeName)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range secPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(tp.KubeArmorPolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, decoyFileDir := range secPolicy.Spec.WannaCry.DecoyFileDir {
			fromSource := ""
			match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, decoyFileDir)
			match.IsFromSource = len(fromSource) > 0
			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.Capability) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		// MatchSyscalls
		for _, syscallRule := range secPolicy.Spec.Syscalls.MatchSyscalls {
			if len(syscallRule.Syscalls) == 0 {
				continue
			}
			fromSource := ""
			syscall := tp.SyscallMatchType{
				Tags:     syscallRule.Tags,
				Message:  syscallRule.Message,
				Severity: syscallRule.Severity,
			}
			if len(syscallRule.FromSource) == 0 {
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 {
						continue
					}
					matches.Policies = append(matches.Policies, match)
				}
				continue
			}

			for _, src := range syscallRule.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Dir) > 0 {
					fromSource = src.Dir
					if !strings.HasSuffix(fromSource, "/") {
						fromSource += "/"
					}
				} else {
					continue
				}
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 {
						continue
					}
					match.IsFromSource = len(fromSource) > 0
					match.Recursive = len(src.Path) == 0 && src.Recursive
					matches.Policies = append(matches.Policies, match)
				}

			}
		}
		// SyscallsMatchPath
		for _, syscallRule := range secPolicy.Spec.Syscalls.MatchPaths {
			if len(syscallRule.Path) == 0 || len(syscallRule.Syscalls) == 0 {
				continue
			}
			fromSource := ""
			syscall := tp.SyscallMatchPathType{
				Tags:     syscallRule.Tags,
				Message:  syscallRule.Message,
				Severity: syscallRule.Severity,
			}
			if len(syscallRule.FromSource) == 0 {
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 && len(match.Resource) == 0 {
						continue
					}
					matches.Policies = append(matches.Policies, match)
					match.Source = syscallRule.Path
				}
				continue
			}

			for _, src := range syscallRule.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Dir) > 0 {
					fromSource = src.Dir
					if !strings.HasSuffix(fromSource, "/") {
						fromSource += "/"
					}
				} else {
					continue
				}
				for _, syscallName := range syscallRule.Syscalls {
					syscall.Syscalls = []string{syscallName}
					match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, syscall)
					if len(match.ResourceType) == 0 && len(match.Resource) == 0 {
						continue
					}
					match.IsFromSource = len(fromSource) > 0
					match.Recursive = len(src.Path) == 0 && src.Recursive
					matches.Policies = append(matches.Policies, match)
				}
			}

		}
	}

	fd.SecurityPoliciesLock.Lock()
	fd.SecurityPolicies[fd.Node.NodeName] = matches
	fd.SecurityPoliciesLock.Unlock()
}

// ===================== //
// == Default Posture == //
// ===================== //

// UpdateDefaultPosture Function
func (fd *Feeder) UpdateDefaultPosture(action string, namespace string, defaultPosture tp.DefaultPosture) {

	fd.DefaultPosturesLock.Lock()
	defer fd.DefaultPosturesLock.Unlock()

	if action == "DELETED" {
		delete(fd.DefaultPostures, namespace)
	} else { // ADDED or MODIFIED
		fd.DefaultPostures[namespace] = defaultPosture
	}
}

// Update Log Fields based on default posture and visibility configuration and return false if no updates
func setLogFields(log *tp.Log, existAllowPolicy bool, defaultPosture string, visibility, containerEvent bool) bool {
	if existAllowPolicy && defaultPosture == "audit" && (*log).Result == "Passed" {
		if containerEvent {
			(*log).Type = "MatchedPolicy"
		} else {
			(*log).Type = "MatchedHostPolicy"
		}

		(*log).PolicyName = "DefaultPosture"
		(*log).Enforcer = "eBPF Monitor"
		(*log).Action = "Audit"

		return true
	}

	if visibility {
		if containerEvent {
			(*log).Type = "ContainerLog"
		} else {
			(*log).Type = "HostLog"
		}

		return true
	}

	return false
}

// ==================== //
// == Policy Matches == //
// ==================== //

func getDirectoryPart(path string) string {
	dir := filepath.Dir(path)
	if strings.HasPrefix(dir, "/") {
		return dir + "/"
	}
	return "__not_absolute_path__"
}
