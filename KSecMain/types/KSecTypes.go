/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

package types

/*
安全策略基础模块--抽象出来的公共部分
*/
type KSecHostPolicyName struct {
	Name string `json:"name"`
}

// KSecSecurityPolicyBase yaml文件的公共部分，对应策略
type KSecSecurityPolicyBase struct {
	Name     string   `json:"name"`
	Module   string   `json:"module"`
	Severity int      `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// KSecSecurityPolicyEventBase 对应的event事件结构体
type KSecSecurityPolicyEventBase struct {
	KSecHostPolicyEventBase `json:",inline"`
	Object                  KSecSecurityPolicyBase `json:"object"`
}

/*
KSecHostPolicyEventBase  Event是接受KSec消息的结构包含type和Obejct两部分
Object对应的是每个模块具体解析的内容
*/
// KSecHostPolicyEventBase event事件结构体公共部分
type KSecHostPolicyEventBase struct {
	Type string `json:"type"`
}

/*
勒索病毒模块
*/

// KSecRansomwareHostPolicyEvent 勒索病毒Event
type KSecRansomwareHostPolicyEvent struct {
	KSecHostPolicyEventBase `json:",inline"`
	Object                  KSecRansomwareHostSecurityPolicy `json:"object"`
}

// KSecRansomwareHostSecurityPolicy 勒索病毒策略--Yaml解析对应的结构体
type KSecRansomwareHostSecurityPolicy struct {
	KSecSecurityPolicyBase `json:",inline"`

	SwitchOn     bool                    `json:"switch-on,omitempty"`
	KillProcess  bool                    `json:"kill-process,omitempty"`
	DecoyFileDir []WannaCryDirType       `json:"decoyFileDir,omitempty"`
	WhiteList    []WannaCryWhiteListType `json:"whiteList,omitempty"`
}
