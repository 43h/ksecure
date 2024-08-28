/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

package module

import (
	"encoding/json"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"reflect"
	"testing"
)

func TestRansomWareModule_GetHostPolicyFromEvent(t *testing.T) {
	type args struct {
		yamlByte  []byte
		writeByte *[]byte
	}

	//初始化Event
	var hostPolicyEvent = tp.KSecRansomwareHostPolicyEvent{
		KSecHostPolicyEventBase: tp.KSecHostPolicyEventBase{
			Type: "ADD",
		},
		Object: tp.KSecRansomwareHostSecurityPolicy{
			KSecSecurityPolicyBase: tp.KSecSecurityPolicyBase{
				Name:     "ransomware-policy",
				Module:   "ransomware",
				Severity: 5,
				Tags:     []string{"security", "ransomware"},
				Message:  "这是勒索病毒的策略",
				Action:   "Block",
			},
			SwitchOn: true,
		},
	}
	var yamlByte []byte
	var arg args
	arg.yamlByte, _ = json.Marshal(hostPolicyEvent)
	arg.writeByte = &yamlByte

	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"测试从PolicyEvent获取策略信息", args{arg.yamlByte, arg.writeByte}, hostPolicyEvent.Object, false},
	}

	m := RansomwareModule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.GetHostPolicyFromCLIEvent(tt.args.yamlByte, tt.args.writeByte)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostPolicyFromCLIEvent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHostPolicyFromCLIEvent() got = %v, want %v", got, tt.want)
			}
			//t.Logf("[PASS]%s", tt.name)

		})
	}
}

func TestRansomWareModule_GetHostPolicyFromCacheYaml(t *testing.T) {
	type args struct {
		yamlByte []byte
	}

	//初始化Event
	hostPolicyEvent := tp.KSecRansomwareHostSecurityPolicy{
		KSecSecurityPolicyBase: tp.KSecSecurityPolicyBase{
			Name:     "ransomware-policy",
			Module:   "ransomware",
			Severity: 5,
			Tags:     []string{"security", "ransomware"},
			Message:  "这是勒索病毒的策略",
			Action:   "Block",
		},
		SwitchOn: true,
	}
	var arg args
	arg.yamlByte, _ = json.Marshal(hostPolicyEvent)

	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"测试从默认路径下读取策略文件获取策略", args{arg.yamlByte}, hostPolicyEvent, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := RansomwareModule{}
			got, err := m.GetHostPolicyFromLocalCacheYaml(tt.args.yamlByte)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostPolicyFromLocalCacheYaml() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHostPolicyFromLocalCacheYaml() got = %v, want %v", got, tt.want)
			}
			//t.Logf("[PASS]%s", tt.name)
		})
	}
}

func Test_fillContent(t *testing.T) {
	tests := []struct {
		name     string
		BaitName string
		wantErr  bool
	}{
		{name: "exist", BaitName: "/usr/.a.txt", wantErr: true},
		{name: "noexist", BaitName: "/h/a.txt", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := fillContent(tt.BaitName); (err == nil) != tt.wantErr {
				t.Errorf("fillContent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
