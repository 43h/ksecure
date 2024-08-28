/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

package module

import (
	"github.com/cilium/ebpf"
	"github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// Module 各个模块的公共方法
type Module interface {
	/*
		功能说明:用于将Karmor工具加载Yaml文件后传递过来的Event事件字节流转换为具体模块的结构体对象
		入参：
		yamlByte:Event事件字节流
		writeByte:用于写入本地文件的策略字节流指针
		返回值：
		interface{}: 模块具体的策略结构体对象
		error: 异常信息
	*/
	GetHostPolicyFromCLIEvent(yamlByte []byte, writeByte *[]byte) (interface{}, error)

	/*
		功能说明: 按模块处理策略为具体的规则，更新eBPF Map,下发规则给内核
		入参：
		id: 当前默认为host,后期支持容器为容器ID
		securityPolicies: 策略数组
		bpflsm:指向bpflsm.BPFEnforcer对象的指针，用于操作eBPF Map
	*/
	UpdateRules(id string, securityPolicies []interface{}, be *bpflsm.BPFEnforcer)

	/*
		功能说明: 从本地缓存的Yaml文件字节流中解析出特性模块的策略内容
		入参：
		yamlByte: 本地缓存的yaml文件转换的[]byte

	*/
	GetHostPolicyFromLocalCacheYaml(yamlByte []byte) (interface{}, error)

	/*
		    功能说明： 接受内核上传的日志
			bpflsm:	 指向bpflsm.BPFEnforcer对象的指针，用于操作eBPF Map
	*/
	ReceiveLog(ringbufMap *ebpf.Map, ruleMap *bpflsm.BPFEnforcer, logger *fd.Feeder)
}
