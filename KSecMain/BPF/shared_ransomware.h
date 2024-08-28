/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

#ifndef __SHARED_RANSOMWARE_H
#define __SHARED_RANSOMWARE_H

#include "shared.h"

#define DIV_FILE_NAME "name"
#define DIV_RELEASE_FILE_OPEN_APP "file_open_release"
#define DIV_WHITE_LIST "wannacry_white"

typedef struct bufkey_ransomware {
  char path[MAX_STRING_SIZE];
  char type[MAX_STRING_SIZE];
} bufs_k_ransomware;

struct bufk_ransomware{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_k_ransomware);
  __uint(max_entries, 4);
};

struct ransomware_decoy{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, bufs_k_ransomware);
  __type(value, u32);
  __uint(max_entries, 1024);
};

struct app_path{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, bufs_k_ransomware);
  __type(value, u32);
  __uint(max_entries, 10);
};

struct ransomware_decoy wc_decoy SEC(".maps");
struct ringbuf_custom rb_ransomware SEC(".maps");
struct bufs_share bufs_ransomware SEC(".maps");
struct bufs_off_share bufs_off_ransomware SEC(".maps");
struct bufk_ransomware bufk_wc SEC(".maps");
//记录要放过的程序路径等
struct app_path white_app_ransom SEC(".maps");

static inline int match_and_enforce_path_ransom_hooks(struct path *f_path, u32 id, u32 eventId ) {
  // "z" is a zero value map key which is used to reset values of other keys
  // which are inturn used and updated to lookup the Rule Map

  // "store" stores informaton needed to do a lookup to our Rule Map

  // "pk" is a map key which is used for all kinds of matching and lookups, We
  // needed a third key because we need to copy contents from store and keep
  // resetting the contents of this key so data in store needs to persist

  u32 zero = 0;
  u32 one = 1;
  u32 two = 2;

  bufs_k_ransomware *z = bpf_map_lookup_elem(&bufk_wc, &zero);
  if (z == NULL)
    return 0;

  //初始化
  bpf_map_update_elem(&bufk_wc, &two, z, BPF_ANY);
  bpf_map_update_elem(&bufk_wc, &one, z, BPF_ANY);

  bufs_k_ransomware *pk = bpf_map_lookup_elem(&bufk_wc, &two);
    if (pk == NULL)
      return 0;

  bufs_k_ransomware *store = bpf_map_lookup_elem(&bufk_wc, &one);
  if (store == NULL)
    return 0;

  /* Extract full path from file structure provided by LSM Hook */
  bpf_probe_read_str(store->path, MAX_STRING_SIZE, get_object_path(f_path, &bufs_ransomware, &bufs_off_ransomware));

  /* Extract full path of the source binary from the task structure */
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  bpf_probe_read_str(store->type, MAX_STRING_SIZE, get_subject_path(t, f_path, &bufs_ransomware, &bufs_off_ransomware));

  //获取文件名称
  struct qstr d_name = BPF_CORE_READ(f_path->dentry, d_name);
  //1.查询是否是勒索文件名
  char baitFileName[] = DIV_FILE_NAME;
  bpf_probe_read_str(pk->path, MAX_STRING_SIZE, d_name.name);
  bpf_probe_read_str(pk->type, MAX_STRING_SIZE, baitFileName);

  u32 *existDecoy = bpf_map_lookup_elem(&wc_decoy, pk);
  bool isCheck = false;
  bool isKill = false;
  //2.是勒索诱饵文件
  //bpf_printk("[ransom_file_open] pk->path:%s\n", pk->path);
  //bpf_printk("[ransom_file_open] pk->type:%s\n", pk->type);
  //bpf_printk("[ransom_file_open] existDecoy:%d\n", existDecoy);
  if(existDecoy) {
     isCheck = true;
     if(*existDecoy==ACTION_BLOCK) {
            isKill = true;
     }
 	 if(match_path("/opt/KSec/bin/KSecMain", store->type) == MATCH_OK){
        return 0;
     }
     //对file_open，放过mv和cp
     if(eventId == _SYS_OPEN){
        bpf_map_update_elem(&bufk_wc, &two, z, BPF_ANY);

        char white_list[] = DIV_RELEASE_FILE_OPEN_APP;
        bpf_probe_read_str(pk->path, MAX_STRING_SIZE, store->type);
        bpf_probe_read_str(pk->type, MAX_STRING_SIZE, white_list);
        u32 *isWhiteForFileOpen = bpf_map_lookup_elem(&white_app_ransom, pk);
        if(isWhiteForFileOpen){
             return 0 ;
        }
     }
  }
  int returnValue = 0;
  if(isCheck) {
     //重写store的值
     bpf_map_update_elem(&bufk_wc, &two, z, BPF_ANY);
     //再查询主体路径是否是白名单
     char white_list[] = DIV_WHITE_LIST;
     bpf_probe_read_str(pk->path, MAX_STRING_SIZE, store->type);
     bpf_probe_read_str(pk->type, MAX_STRING_SIZE, white_list);

     u32 *existWhitelist = bpf_map_lookup_elem(&wc_decoy, pk);
     if(existWhitelist){
         returnValue =  -EPERM;
     }else{

        send_security_log(t, store->path, store->type, eventId, 2, &rb_ransomware);

        //判断是否拦截
        if(isKill) {
              //杀死当前进程
              bpf_send_signal(9);
        }
        returnValue = -EPERM;
     }

  }
  //bpf_printk("[ransom_file_open] resultValue:%d\n", returnValue);

  return returnValue;
}

#endif /* __SHARED_H */
