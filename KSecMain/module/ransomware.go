/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

package module

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/cilium/ebpf"
	ring "github.com/cilium/ebpf/ringbuf"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	"github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	logger "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RansomwareModule
/**
勒索病毒防护模块类，实现诱饵文件投放，策略下发，捕获诱饵文件被编辑的操作
实现module{}中的接口
UpdateRules函数用于更新策略到内核
ReceiveLog函数用于接口内核RingBuff上报的日志
GetHostPolicyFromCLIEvent和GetHostPolicyFromLocalCacheYaml用于解析策略Yaml
*/
type RansomwareModule struct {
	SecLogChannel chan []byte
}

func NewRansomwareModule() RansomwareModule {
	creatHomeCustomDir()
	createBaitFileNames()
	return RansomwareModule{}
}

// RansomKey 勒索病毒规则Map的Key，用于和内核交互
type RansomKey struct {
	Path [256]byte
	Type [256]byte
}

// 诱饵文件名称集合
var baitFileNames []string

// 全局更新是否Kill进程
var ransomAction = kl.RansomActionNotKill

// home目录路径
var homePath = "/home"

// home目录下自定义诱饵目录的名称
var homeCustomDirName = ".kSec"

// 对fileOpen hook点放过的程序，遇到直接放过
var releaseAppForFileOpen = []string{"/usr/bin/mv", "/usr/bin/cp"}

// 默认白名单程序
var whiteListDefault = []string{"/opt/KSec/bin/KSecMain", "/usr/bin/userdel", "/usr/libexec/gvfsd-trash"}

// 默认诱饵投放目录
var baitDirDefault = []string{"/home/.kSec", "/", "/etc/fonts", "/root/.cache", "/root/.dbus", "/root/.config", "/root/.local", "/root/Desktop",
	"/root/桌面", "/var/tmp", "/var/lib", "/var/log", "/var/adm", "/var/cache", "/usr/bin", "/usr/lib/debug", "/usr/lib/systemd",
	"/usr/lib/grub", "/boot/efi"}

// 诱饵前后缀
var baitNameStartAndSuffix = [2][2]string{{".00", ".docx"}, {".ZZ", ".docx"}}

// 日志内容: 是否Kill
var isKill bool

func (m RansomwareModule) GetHostPolicyFromCLIEvent(yamlByte []byte, writeByte *[]byte) (interface{}, error) {
	var ransomwarePolicyEvent tp.KSecRansomwareHostPolicyEvent
	err := json.Unmarshal(yamlByte, &ransomwarePolicyEvent)
	if err != nil {
		return nil, err
	}

	*writeByte, err = json.Marshal(ransomwarePolicyEvent.Object)
	return ransomwarePolicyEvent.Object, err
}

func (m RansomwareModule) GetHostPolicyFromLocalCacheYaml(yamlByte []byte) (interface{}, error) {
	var ransomwareHostPolicy tp.KSecRansomwareHostSecurityPolicy
	err := json.Unmarshal(yamlByte, &ransomwareHostPolicy)
	if err != nil {
		return nil, err
	}
	return ransomwareHostPolicy, nil
}

// UpdateRules 更新勒索策略到内核
func (m RansomwareModule) UpdateRules(_ string, securityPolicies []interface{}, be *bpflsm.BPFEnforcer) {

	updateBaitFileNameInMap(be.ObjRansomWare.WhiteAppRansom)

	creatHomeCustomDir()

	if len(securityPolicies) == 0 {
		delPolicyAndBaits(be.ObjRansomWare.WcDecoy)
		return
	}

	ransomwarePolicy, ok := securityPolicies[0].(tp.KSecRansomwareHostSecurityPolicy)

	if !(ok && ransomwarePolicy.SwitchOn) {
		delPolicyAndBaits(be.ObjRansomWare.WcDecoy)
		return
	}
	//是否KIll
	if ransomwarePolicy.KillProcess {
		ransomAction = kl.RansomActionKill
	} else {
		ransomAction = kl.RansomActionNotKill
	}

	baitRealDirs := getBaitDir(ransomwarePolicy)

	//设置白名单
	setRansomWhiteMap(ransomwarePolicy.WhiteList, be.ObjRansomWare.WcDecoy)

	delFileNameInMap(be.ObjRansomWare.WcDecoy)

	baitFilePaths := make([]string, 0)
	creatBaitsAndMap(baitRealDirs, be.ObjRansomWare.WcDecoy, &baitFilePaths)
	delPolicyAndBaits(be.ObjRansomWare.WcDecoy)
	addFileNameInMap(be.ObjRansomWare.WcDecoy)
	//更新日志中要使用的killProcess-作为日志中的Action字段
	updateMessageForLog(ransomwarePolicy.KillProcess)
}

// 更新Map中-file_open的白名单程序，直接放过
func updateBaitFileNameInMap(whiteAppMap *ebpf.Map) {
	for _, appPath := range releaseAppForFileOpen {
		var key RansomKey
		copy(key.Path[:], appPath)
		copy(key.Type[:], kl.RansomReleaseAppInFileOpenType)
		err := whiteAppMap.Put(key, kl.RansomActionTemp)
		if err != nil {
			logger.Warnf("更新创建文件放过程序路径：%s", err)
		}
	}
}

// 更新诱饵文件名称到内核Map中
func addFileNameInMap(decoy *ebpf.Map) {
	for _, fileName := range baitFileNames {
		err := addRansomMap(decoy, fileName, kl.RansomFileName)
		if err != nil {
			logger.Warnf("添加勒索诱饵文件策略失败 : %s,%s", fileName, err)
		}
	}
}

// 更新勒索策略Map的方法
func addRansomMap(decoy *ebpf.Map, fileName, fileType string) error {
	var key RansomKey
	copy(key.Path[:], fileName)
	copy(key.Type[:], fileType)
	return decoy.Put(key, ransomAction)
}

// 删除内核Map中的文件名
func delFileNameInMap(decoy *ebpf.Map) {
	for _, fileName := range baitFileNames {
		_ = delRansomMap(decoy, fileName, kl.RansomFileName)
	}
}

// 更新日志中的消息：处置动作
func updateMessageForLog(killProcess bool) {
	isKill = killProcess
}

// 创建/home目录下的自定义目录
func creatHomeCustomDir() {
	path := filepath.Join(homePath, homeCustomDirName)
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		_ = os.Mkdir(path, 0755)
	}
}

/*
获取诱饵投放目录：
return：baitRealDirs 诱饵投放目录，包括默认路径+home下用户主目录前5个+自定义路径
*/
func getBaitDir(ransomwarePolicy tp.KSecRansomwareHostSecurityPolicy) []string {
	//1.home下用户主目录(前5个)投放诱饵
	userHomeDir := getUserHomeDir()

	//2.默认目录+自定义目录,自定义目录最多100个
	baitRealDirs := baitDirDefault
	for index, dir := range ransomwarePolicy.DecoyFileDir {
		if index >= 100 {
			//限制最多前100个自定义目录生效
			break
		}
		baitRealDirs = append(baitRealDirs, dir.Dir)
	}

	for _, path := range userHomeDir {
		baitRealDirs = append(baitRealDirs, path)
	}

	return baitRealDirs
}

// 获取自定义用户在/home下的用户主目录路径
func getUserHomeDir() []string {

	var userHomeDir []string

	files, err := os.ReadDir(homePath)
	if err != nil {
		logger.Errf("get file form /home has error :%s", err)
		return userHomeDir
	}

	index := 1
	for _, file := range files {
		if file.IsDir() && file.Name() != homeCustomDirName && !strings.HasPrefix(file.Name(), ".") {
			logger.Printf("/home`s sub dir: %s", file.Name())
			userHomeDir = append(userHomeDir, filepath.Join(homePath, file.Name()))
			if index >= 5 {
				//只取前5个用户主目录
				break
			}

			index++
		}
	}
	return userHomeDir

}

// ReceiveLog 接受内核上报日志
func (m RansomwareModule) ReceiveLog(ringbufMap *ebpf.Map, ruleMap *bpflsm.BPFEnforcer, logger *fd.Feeder) {
	secLogRingBuf, err := ring.NewReader(ringbufMap)
	if err != nil {
		logger.Errf("ring.NewReader(be.ObjRansomDetect.Rb) err : %s", err)
		return
	}

	m.SecLogChannel = make(chan []byte, kl.SecLogChannelSize)

	if secLogRingBuf != nil {
		go func() {
			for {
				record, err := secLogRingBuf.Read()
				if err != nil {
					if errors.Is(err, ring.ErrClosed) {
						logger.Warnf("ring Buffer closed, exiting ReceiveLog %s", err.Error())
						return
					}
					continue
				}

				m.SecLogChannel <- record.RawSample
			}
		}()
	} else {
		logger.Err("Ring Buf nil, exiting ReceiveLog")
		return
	}

	var secLog tp.SecLog
	var event kl.Events
	for {
		select {
		case dataRaw, valid := <-m.SecLogChannel:
			if !valid {
				continue
			}
			dataBuff := bytes.NewBuffer(dataRaw)

			if err = binary.Read(dataBuff, binary.LittleEndian, &event); err != nil {
				logger.Printf("parsing ring buff event:%s", err)
				continue
			}

			secLog.Time = time.Now().Format("2006-01-02 15:04:05")
			secLog.User = getUserFromUID(event.UID)
			secLog.PID = event.PID
			secLog.Path = kl.TrimString(string(event.Path[:]))
			secLog.Source = kl.TrimString(string(event.Source[:]))
			secLog.PPID = event.PPID
			secLog.Action = getIsKillForLog()

			go logger.PushSecLog(secLog)
		}
	}
}

// 打印处理动作是kill还是block
func getIsKillForLog() string {
	if isKill == true {
		return "kill"
	} else {
		return "block"
	}
}

// 根据UID获取用户登录名
func getUserFromUID(uid uint32) string {

	uidStr := strconv.FormatUint(uint64(uid), 10)
	userInfo, err := user.LookupId(uidStr)
	if err != nil {
		return ""
	}
	return userInfo.Username

}

// 生成诱饵文件名称-前缀+随机字符+后缀
func createBaitFileNames() {
	//初始化
	baitFileNames = make([]string, 0)

	//缓存勒索文件名称
	randString := createRandBaitName()
	generateFileName(randString, &baitFileNames)
}

// 生成文件名
func generateFileName(randString string, baitFileNames *[]string) {
	for _, StartAndSuffix := range baitNameStartAndSuffix {
		var buffer bytes.Buffer
		buffer.WriteString(StartAndSuffix[0])
		buffer.WriteString(randString)
		if StartAndSuffix[1] != "" {
			buffer.WriteString(StartAndSuffix[1])
		}
		logger.Debugf("create bait file name:%s", buffer.String())
		*baitFileNames = append(*baitFileNames, buffer.String())
	}
}

// 生成诱饵目录名称
func createRandBaitName() string {
	cmd := exec.Command("/usr/sbin/dmidecode", "-s", "system-uuid")
	output, err := cmd.Output()
	if err == nil && len(output) >= 34 {
		return string(output[26:34])
	}
	return "suiji008"
}

// 生成并填充诱饵
func fillContent(baitNameWithDir string) error {
	fileInfo, err := os.Stat(baitNameWithDir)
	if !os.IsNotExist(err) && fileInfo.Size() > 0 {
		return nil
	}

	logger.Printf("填充诱饵文件:%s", baitNameWithDir)
	file, err := os.OpenFile(baitNameWithDir, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	write := bufio.NewWriter(file)
	for i := 0; i < 50; i++ {
		_, err := write.WriteString("此文件为勒索病毒诱饵文件，请勿操作！！！")
		if err != nil {
			continue
		}
	}

	err = write.Flush()
	if err != nil {
		return err
	}
	return nil
}

// 删除诱饵文件
func deleteBaits(baitNames string) {
	err := os.Remove(baitNames)
	if err != nil {
		logger.Printf("文件：%s删除失败,%s", baitNames, err)
	} else {
		logger.Debugf("文件：%s删除成功", baitNames)
	}
}

// 生成全路径诱饵名称
func generateBaitName(dir, fileName string) string {
	var BaitDirWithName bytes.Buffer
	BaitDirWithName.WriteString(dir)
	separator := string(os.PathSeparator)
	if dir[len(dir)-1:] != separator {
		BaitDirWithName.WriteString(separator)
	}
	BaitDirWithName.WriteString(fileName)
	return BaitDirWithName.String()
}

// 获取勒索策略map中path，返回path数组
func delPolicyAndBaits(wcDecoyMap *ebpf.Map) {
	var (
		KEY       RansomKey
		VALUE     uint32
		baitNames []string
	)
	iterateDelete := wcDecoyMap.Iterate()
	for iterateDelete.Next(&KEY, &VALUE) {
		KEY := KEY
		VALUE := VALUE
		if VALUE == kl.RansomActionTemp {
			continue
		}
		if kl.TrimString(string(KEY.Type[:])) == kl.RansomDecoy {
			var err = delRansomMap(wcDecoyMap, kl.TrimString(string(KEY.Path[:])), kl.RansomDecoy)
			if err != nil {
				logger.Warnf("删除诱饵防护策略失败 : %s,%s", kl.TrimString(string(KEY.Path[:])), err)
			} else {
				baitNames = append(baitNames, kl.TrimString(string(KEY.Path[:])))
			}
		} else if kl.TrimString(string(KEY.Type[:])) == kl.RansomFileName {
			var err = delRansomMap(wcDecoyMap, kl.TrimString(string(KEY.Path[:])), kl.RansomFileName)
			if err != nil {
				logger.Warnf("删除勒索文件名称失败 : %s,%s", kl.TrimString(string(KEY.Path[:])), err)
			}
		}
	}
	delRansomBaits(baitNames)
	iterateUpdate := wcDecoyMap.Iterate()
	for iterateUpdate.Next(&KEY, &VALUE) {
		KEY := KEY
		VALUE := VALUE
		if VALUE == kl.RansomActionTemp {
			var err = wcDecoyMap.Put(KEY, ransomAction)
			if err != nil {
				logger.Warnf("更新诱饵策略失败 : %s,%s", kl.TrimString(string(KEY.Path[:])), err)
			}
		}
	}
}

// 删除map中策略
func delRansomMap(wcWhiteMap *ebpf.Map, baitPath string, ransomSource string) error {
	var wcKey RansomKey
	copy(wcKey.Path[:], baitPath)
	copy(wcKey.Type[:], ransomSource)
	return wcWhiteMap.Delete(wcKey)
}

// 删除诱饵文件
func delRansomBaits(baitNames []string) {
	for i := range baitNames {
		deleteBaits(baitNames[i])
	}
}

// 批量生成诱饵文件
func creatBaitsAndMap(baitDirs []string, wcDecoyMap *ebpf.Map, baitFilePaths *[]string) {
	//遍历诱饵目录
	for _, BaitDir := range baitDirs {
		generateBaitFile(BaitDir, wcDecoyMap, baitFilePaths, baitFileNames)
	}
}

// 为诱饵目录投放
func generateBaitFile(BaitDir string, wcDecoyMap *ebpf.Map, baitFilePaths *[]string, baitFileNames []string) {
	for _, fileName := range baitFileNames {
		var wcKey RansomKey

		baitNameWithDir := generateBaitName(BaitDir, fileName)

		errFill := fillContent(baitNameWithDir)
		if errFill != nil {
			continue
		}

		errChmod := os.Chmod(baitNameWithDir, 0666)
		if errChmod != nil {
			logger.Warnf("chmod err : %s", baitNameWithDir)
		}

		copy(wcKey.Path[:], baitNameWithDir)
		for i := 0; i < len(kl.RansomDecoy); i++ {
			wcKey.Type[i] = kl.RansomDecoy[i]
		}
		err := wcDecoyMap.Put(wcKey, kl.RansomActionTemp)
		if err != nil {
			logger.Warnf("诱饵路径： %s", string(wcKey.Path[:]))
			logger.Warnf("更新诱饵map失败： %s", err)
		}

		*baitFilePaths = append(*baitFilePaths, baitNameWithDir)
	}
}

// 添加白名单策略
func setRansomWhiteMap(wcWhiteList []tp.WannaCryWhiteListType, wcWhiteMap *ebpf.Map) {
	//Yaml配置的
	for index, path := range wcWhiteList {
		if index >= 100 {
			//限制Yaml中配置的白名单前100个生效
			break
		}
		updateWhiteListMap(path.Path, wcWhiteMap)
	}
	//默认的
	for _, whiteList := range whiteListDefault {
		updateWhiteListMap(whiteList, wcWhiteMap)
	}
}

// 更新白名单程序map
func updateWhiteListMap(path string, wcWhiteMap *ebpf.Map) {
	var wcWhiteListKey RansomKey
	copy(wcWhiteListKey.Path[:], path)
	for i := 0; i < len(kl.RansomWhite); i++ {
		wcWhiteListKey.Type[i] = kl.RansomWhite[i]
	}
	err := wcWhiteMap.Put(wcWhiteListKey, kl.RansomActionTemp)
	if err != nil {
		logger.Warnf("更新白名单失败： %s", err)
	}
}
