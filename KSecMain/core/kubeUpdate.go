// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"encoding/json"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	module "github.com/kubearmor/KubeArmor/KubeArmor/module"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"os"
	"path/filepath"
	"regexp"
	"sigs.k8s.io/yaml"
	"strings"
)

// ================= //
// == Node Update == //
// ================= //

// HandleNodeAnnotations Handle Node Annotations i.e, set host visibility based on annotations, enable/disable policy
func (dm *KubeArmorDaemon) HandleNodeAnnotations(node *tp.Node) {
	if _, ok := node.Annotations["kubearmor-policy"]; !ok {
		node.Annotations["kubearmor-policy"] = "enabled"
	}

	if node.Annotations["kubearmor-policy"] != "enabled" && node.Annotations["kubearmor-policy"] != "disabled" && node.Annotations["kubearmor-policy"] != "audited" {
		node.Annotations["kubearmor-policy"] = "enabled"
	}

	if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		if !strings.Contains(string(lsm), "apparmor") && !strings.Contains(string(lsm), "selinux") {
			// exception: neither AppArmor nor SELinux
			if node.Annotations["kubearmor-policy"] == "enabled" {
				node.Annotations["kubearmor-policy"] = "audited"
			}
		}

		if kl.IsInK8sCluster() && strings.Contains(string(lsm), "selinux") {
			// exception: KubeArmor in a daemonset even though SELinux is enabled
			if node.Annotations["kubearmor-policy"] == "enabled" {
				node.Annotations["kubearmor-policy"] = "audited"
			}
		}
	}

	if node.Annotations["kubearmor-policy"] == "enabled" {
		node.PolicyEnabled = tp.KubeArmorPolicyEnabled
	} else if node.Annotations["kubearmor-policy"] == "audited" {
		node.PolicyEnabled = tp.KubeArmorPolicyAudited
	} else { // disabled
		node.PolicyEnabled = tp.KubeArmorPolicyDisabled
	}
}

// ================================= //
// == Host Security Policy Update == //
// ================================= //

// UpdateHostSecurityPolicies Function
func (dm *KubeArmorDaemon) UpdateHostSecurityPolicies(module string) {
	//这段是为了文件防护当前日志匹配的逻辑，日志改造的时候同步修改
	secPolicies := []tp.HostSecurityPolicy{}

	dm.Logger.UpdateHostSecurityPolicies("UPDATED", secPolicies)

	if dm.RuntimeEnforcer != nil {
		if dm.Node.PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// enforce host security policies
			dm.RuntimeEnforcer.UpdateHostSecurityPolicies(module, dm.HostSecurityPolicyMap[module])
		}
	}
}

func (dm *KubeArmorDaemon) GetHostSecurityPolicy() *map[string][]interface{} {
	res := &dm.HostSecurityPolicyMap
	return res
}

// ParseAndUpdateHostSecurityPolicy Function
func (dm *KubeArmorDaemon) ParseAndUpdateHostSecurityPolicy(policyData []byte, eventBase tp.KSecSecurityPolicyEventBase) {
	var yamlByte []byte
	//获取特性的实例
	moduleObject := module.ModuleObjectMap[eventBase.Object.Module]
	//解析为实例对象
	policyEvent, err := moduleObject.GetHostPolicyFromCLIEvent(policyData, &yamlByte)
	if err == nil {
		err = dm.UpdateHostSecuirtyPolicyMap(eventBase, eventBase.Object.Name, eventBase.Object.Module, policyEvent)
		if err != nil {
			return
		}
	} else {
		return
	}

	dm.Logger.Printf("Detected a Host Security Policy (%s/%s)", strings.ToLower(eventBase.Type), eventBase.Object.Name)

	// apply security policies to a host
	dm.UpdateHostSecurityPolicies(eventBase.Object.Module)

	//zhenpeng modify to ==
	if eventBase.Type == "ADDED" || eventBase.Type == "MODIFIED" {
		// backup HostSecurityPolicy to file
		dm.backupKubeArmorHostPolicy(yamlByte, eventBase.Object.Name)
	} else if eventBase.Type == "DELETED" {
		dm.removeBackUpPolicy(eventBase.Object.Name)
	}
	//zhenpeng modify end ==
}

func (dm *KubeArmorDaemon) UpdateHostSecuirtyPolicyMap(event tp.KSecSecurityPolicyEventBase, curPolicyName, mapKey string, value interface{}) error {
	// update a security policy into the policy list
	dm.HostSecurityPolicyMapLock.Lock()
	var hostSecuirtyPolicyMapValue = dm.HostSecurityPolicyMap[mapKey]
	if event.Type == "ADDED" {
		//不支持同时导入多个策略文件的特性使用新的逻辑
		if mapKey == kl.RansomModule {
			if hostSecuirtyPolicyMapValue != nil && len(hostSecuirtyPolicyMapValue) > 0 {
				//已经加过策略,需要判断是否需要删除旧策略的缓存文件
				policy := hostSecuirtyPolicyMapValue[0]
				securityPolicyName := module.GetHostPolicyName(policy, mapKey)
				if securityPolicyName != curPolicyName {
					kg.Debugf("添加策略名与当前策略不一致，删除当前策略：", securityPolicyName, "新策略:", curPolicyName)
					//如果新导入的策略名和旧的不一致，需要删除旧策略的缓存文件
					dm.removeBackUpPolicy(securityPolicyName)
				}
				dm.HostSecurityPolicyMap[mapKey][0] = value
			} else {
				//如果从来没有加过策略,就直接加上
				dm.HostSecurityPolicyMap[mapKey] = append(dm.HostSecurityPolicyMap[mapKey], value)
			}

		} else {
			//支持同时导入多个策略文件的特性使用原有的功能
			new := true
			for idx, policy := range hostSecuirtyPolicyMapValue {
				securityPolicyName := module.GetHostPolicyName(policy, mapKey)
				if securityPolicyName == curPolicyName {
					dm.HostSecurityPolicyMap[mapKey][idx] = value
					event.Type = "MODIFIED"
					new = false
					break
				}
			}
			if new {
				dm.HostSecurityPolicyMap[mapKey] = append(dm.HostSecurityPolicyMap[mapKey], value)
			}
		}
	} else if event.Type == "MODIFIED" {
		for idx, policy := range hostSecuirtyPolicyMapValue {
			securityPolicyName := module.GetHostPolicyName(policy, mapKey)
			if securityPolicyName == curPolicyName {
				dm.HostSecurityPolicyMap[mapKey][idx] = value
				break
			}
		}
	} else if event.Type == "DELETED" {
		for idx, policy := range hostSecuirtyPolicyMapValue {
			securityPolicyName := module.GetHostPolicyName(policy, mapKey)
			if securityPolicyName == curPolicyName {
				dm.HostSecurityPolicyMap[mapKey] = deleteValueInPolicyMap(dm.HostSecurityPolicyMap[mapKey], idx)
				break
			}
		}
	}

	dm.HostSecurityPolicyMapLock.Unlock()
	return nil
}

func deleteValueInPolicyMap(policies []interface{}, idx int) []interface{} {
	var newPolicy []interface{}
	for index, policy := range policies {
		if index == idx {
			continue
		} else {
			newPolicy = append(newPolicy, policy)
		}
	}
	return newPolicy
}

// ================================= //
// == HostPolicy Backup & Restore == //
// ================================= //

// backupKubeArmorHostPolicy Function
func (dm *KubeArmorDaemon) backupKubeArmorHostPolicy(policyBytes []byte, policyName string) {
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(cfg.PolicyDir); err != nil {
		if err = os.MkdirAll(cfg.PolicyDir, 0700); err != nil {
			kg.Warnf("Dir creation failed for [%v]", cfg.PolicyDir)
			return
		}
	}

	var file *os.File
	var err error

	if file, err = os.Create(cfg.PolicyDir + policyName + ".yaml"); err == nil {
		if _, err = file.Write(policyBytes); err == nil {
			if err := file.Close(); err != nil {
				dm.Logger.Errf(err.Error())
			}
		}
	}
}

// Back up KubeArmor container policies in /opt/kubearmor/policies
func (dm *KubeArmorDaemon) backupKubeArmorContainerPolicy(policy tp.SecurityPolicy) {
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(cfg.PolicyDir); err != nil {
		if err = os.MkdirAll(cfg.PolicyDir, 0700); err != nil {
			kg.Warnf("Dir creation failed for [%v]", cfg.PolicyDir)
			return
		}
	}

	var file *os.File
	var err error

	if file, err = os.Create(cfg.PolicyDir + policy.Metadata["policyName"] + ".yaml"); err == nil {
		if policyBytes, err := json.Marshal(policy); err == nil {
			if _, err = file.Write(policyBytes); err == nil {
				if err := file.Close(); err != nil {
					dm.Logger.Errf(err.Error())
				}
			}
		}
	}
}

// removeBackUpPolicy Function
func (dm *KubeArmorDaemon) removeBackUpPolicy(name string) {

	fname := cfg.PolicyDir + name + ".yaml"
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(fname); err != nil {
		kg.Printf("Backup policy [%v] not exist", fname)
		return
	}

	if err := os.Remove(fname); err != nil {
		kg.Errf("unable to delete file:%s err=%s", fname, err.Error())
	}
}

func (dm *KubeArmorDaemon) getKubeArmorHostPolicies(path string) error {
	policyFile, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}

	policies := strings.Split(string(policyFile), "---")

	for _, policy := range policies {

		if matched, _ := regexp.MatchString("^\\s*$", policy); matched {
			continue
		}

		js, err := yaml.YAMLToJSON([]byte(policy))
		if err != nil {
			return err
		}

		var baseHostPolicy tp.KSecSecurityPolicyBase
		if err := json.Unmarshal(js, &baseHostPolicy); err == nil {
			//获取特性的实例
			//按模块处理
			if (!cfg.GlobalCfg.EnableRansomWareProtect) && (kl.RansomModule == baseHostPolicy.Module) {
				kg.Warn("RansomWare module is not loaded,did not load policies")
				continue
			}
			moduleObject := module.ModuleObjectMap[baseHostPolicy.Module]
			hostPolicy, error := moduleObject.GetHostPolicyFromLocalCacheYaml(js)
			if error != nil {
				kg.Errf("GetHostPolicyFromLocalCacheYaml has error:%s", error)
				continue
			}
			dm.HostSecurityPolicyMap[baseHostPolicy.Module] = append(dm.HostSecurityPolicyMap[baseHostPolicy.Module], hostPolicy)
		}
	}
	return nil
}

func (dm *KubeArmorDaemon) loadKubeArmorHostPolicies() {

	err := dm.getKubeArmorHostPolicies(cfg.GlobalCfg.YamlPath)
	if err != nil {
		kg.Errf("Reading policies file has error:s%", err)
	}

	if cfg.GlobalCfg.EnableRansomWareProtect {
		dm.UpdateHostSecurityPolicies(kl.RansomModule)
	}

}
