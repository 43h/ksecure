// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package policy handles policy updates over gRPC in non-k8s environment
package policy

import (
	"context"
	"encoding/json"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	pb "github.com/kubearmor/KubeArmor/KubeArmor/protobuf"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ServiceServer provides structure to serve Policy gRPC service
type ServiceServer struct {
	pb.PolicyServiceServer
	UpdateContainerPolicy func(tp.K8sKubeArmorPolicyEvent)
	UpdateHostPolicy      func([]byte, tp.KSecSecurityPolicyEventBase)
	GetHostPolicyMap      func() *map[string][]interface{}
}

// ContainerPolicy accepts container events on gRPC and update container security policies
func (p *ServiceServer) ContainerPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	policyEvent := tp.K8sKubeArmorPolicyEvent{}
	res := new(pb.Response)

	err := json.Unmarshal(data.Policy, &policyEvent)

	if err == nil {

		if policyEvent.Object.Metadata.Name != "" {

			p.UpdateContainerPolicy(policyEvent)

			res.Status = 1

		} else {

			kg.Warn("Empty Container Policy Event")

			res.Status = 0
		}

	} else {
		kg.Warn("Invalid Container Policy Event")
		res.Status = 0
	}

	return res, nil
}

// HostPolicy accepts host policy event on gRPC service and updates host security policies. It responds with 1 if success else 0.
func (p *ServiceServer) HostPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	policyEvent := tp.KSecSecurityPolicyEventBase{}
	res := new(pb.Response)
	err := json.Unmarshal(data.Policy, &policyEvent)
	if err == nil {
		if policyEvent.Object.Name != "" {
			//按模块处理
			if (!cfg.GlobalCfg.EnableRansomWareProtect) && (kl.RansomModule == policyEvent.Object.Module) {
				res.Status = 2
				return res, nil
			}
			//这里也可以根据模块解析出来具体的策略，后面兼容K8s的时候可以修改
			p.UpdateHostPolicy(data.Policy, policyEvent)
			res.Status = 1
		} else {
			kg.Warn("Empty Host Policy Event")
			res.Status = 0
		}
	} else {
		kg.Warn("Invalid Host Policy Event")
		res.Status = 0
	}

	return res, nil
}

// GetHostPolicy show ransomware policy.
func (p *ServiceServer) GetHostPolicy(c context.Context, data *pb.PolicyRequest) (*pb.PolicyResponse, error) {
	remap := p.GetHostPolicyMap()
	policyRe := new(pb.PolicyResponse)
	for _, policyAll := range *remap {
		for _, policy := range policyAll {
			policyByte, _ := json.Marshal(policy)
			policyObj := new(pb.RePolicyObj)
			policyObj.Name = kl.TrimString(string(policyByte))
			policyRe.RePolicy = append(policyRe.RePolicy, policyObj)
		}
	}
	return policyRe, nil
}
