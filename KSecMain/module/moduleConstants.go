/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

package module

import (
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"sync"
)

// ModuleObjectMap Module Set --记录加载的模块信息
var ModuleObjectMap = map[string]Module{}

// ModuleMapLock 锁
var ModuleMapLock = new(sync.RWMutex)

// GetHostPolicyName 获取策略命令，按特性解析
func GetHostPolicyName(policy interface{}, module string) string {
	switch module {
	case kl.RansomModule:
		securityPolicy := policy.(tp.KSecRansomwareHostSecurityPolicy)
		return securityPolicy.Name
	default:
		return ""
	}
}
