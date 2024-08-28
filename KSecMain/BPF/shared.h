/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 Authors of KubeArmor */

#ifndef __SHARED_H
#define __SHARED_H

#include "vmlinux.h"
#include "vmlinux_macro.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*勒索病毒诱捕*/
//LSM拦截返回值
#define EPERM 13
//BUF的长度
#define MAX_BUFFER_SIZE 32768
#define MAX_STRING_SIZE 256
//MAP获取BUF用
#define MAX_BUFFERS 2
#define PATH_BUFFER 0
#define FILE_ATTR_BUFFER 1
#define TASK_COMM_LEN 16
/*勒索病毒拦截标志*/
#define ACTION_BLOCK 1

/*勒索病毒用权限*/
#define MODE_READ 0x00000001
//FMODE_PREAD标示文件支持pread()系统调用
#define MODE_PREAD 0x00000010
#define MODE_WRITE 0x00000002
#define MODE_APPEND 0x00000008
#define MODE_PWRITE 0x00000010

#define SIGCONT		18
#define SIGSTOP		19

#ifdef __CHECKER__
#define __force __attribute__(force)
#else
#define __force
#endif

#define FMODE_READ     ((__force fmode_t)0x1)
#define FMODE_WRITE    ((__force fmode_t)0x2)
#define FMODE_PREAD     ((__force fmode_t)0x8)
#define FMODE_PWRITE    ((__force fmode_t)0x10)

#define END_CHAR '\0'
#define SPLIT_CHAR '/'

#define MATCH_OK 0
#define MATCH_FAIL 1
/*CORE读取值*/
#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })
/*通过成员变量获取结构体*/
#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
/*共用系统调用枚举*/
enum
{
    // file
    _SYS_OPEN = 2,
    _SYS_UNLINK = 87,
    _SYS_RENAME = 666,
};
/*共用hook类型*/
enum file_hook_type { dpath = 0, dfileread, dfilewrite, dfileexec, dfiledel, dfilecreate, dprockill, dfilemv};
/*共用结构体*/
typedef struct buffers {
  char buf[MAX_BUFFER_SIZE];
} bufs_t;

typedef struct bufkey {
  char path[MAX_STRING_SIZE];
} bufs_k;

struct bufs_share {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
};

struct bufs_off_share {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
};
/*共用日志结构体*/
typedef struct sec_event{
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 module_id;
    u32 event_id;

    char path[MAX_STRING_SIZE];
    char source[MAX_STRING_SIZE];

    char comm[TASK_COMM_LEN];
} sec_event_t;
/*共用ring buf*/
struct ringbuf_custom {
   __uint(type,BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries,256 * 1024);
};

static __always_inline void set_buf_off(int buf_idx, u32 new_off,struct bufs_off_share *bufs_off) {
  bpf_map_update_elem(bufs_off, &buf_idx, &new_off, BPF_ANY);
}

//获取脚本路径相关map
#define MAX_PERCPU_BUFSIZE (1 << 15)

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                             \
        struct {                                                                                \
                __uint(type, _type);                                                            \
                __uint(max_entries, _max_entries);                                              \
                __type(key, _key_type);                                                         \
                __type(value, _value_type);                                                     \
        } _name SEC(".maps");

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                                      \
        BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

enum buf_idx_e
{
        STRING_BUF_IDX,
        FILE_BUF_IDX,
        THREE,
	      FOUR,
        FIVE,
        MAX_BUFS
};

enum buf_idx_pro
{
        ONE,
        TWO,
        MAX_PROS
};

typedef struct simple_buf {
        char buf[MAX_PERCPU_BUFSIZE];
} buf_t;

BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFS);

static __always_inline buf_t *get_script_buf(int idx)
{
        return bpf_map_lookup_elem(&bufs, &idx);
}

/*计算实际挂载点*/
static struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}
/*字符串匹配*/
static int match_path(const char *rule_path, const char *path)
{
        int i;

#pragma unroll
        for(i = 0; i < 128; i++)
        {
                switch(*rule_path){
                case END_CHAR:
                        if(*path == END_CHAR || *path == SPLIT_CHAR)
                        {
                                return MATCH_OK;
                        }
                        else
                        {
                                return MATCH_FAIL;
                        }
                case SPLIT_CHAR:
                        if(*(rule_path + 1) == END_CHAR && (*path == SPLIT_CHAR || *path == END_CHAR))
                        {
                                return MATCH_OK;
                        }
                        else if(*(rule_path + 1) != END_CHAR)
                        {
                                break;
                        }
                default:
                        if(*path != *rule_path)
                        {
                                return MATCH_FAIL;
                        }
                }

                rule_path++;
                path++;
        }
	return MATCH_FAIL;
}
/*通过实际挂载点计算真实路径*/
static __always_inline bool prepend_path(struct path *path, bufs_t *string_p, struct bufs_off_share *bufs_off) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_STRING_SIZE;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    // get d_name
    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int sz = bpf_probe_read_str(
        &(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]),
        (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1,
          &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_STRING_SIZE) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
  set_buf_off(PATH_BUFFER, offset, bufs_off);
  return true;
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

static struct file *get_task_file(struct task_struct *task) {
  return BPF_CORE_READ(task, mm, exe_file);
}

static bool is_owner(struct file *file_p) {
  kuid_t owner = BPF_CORE_READ(file_p, f_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

static bool is_owner_path(struct dentry *dent) {
  kuid_t owner = BPF_CORE_READ(dent, d_inode, i_uid);
  unsigned int z = bpf_get_current_uid_gid();
  if (owner.val != z)
    return false;
  return true;
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->parent);
    return READ_KERN(parent->pid);
}

static __always_inline bufs_t *get_buf(struct bufs_share *bufs, int idx) {
  return bpf_map_lookup_elem(bufs, &idx);
}

static __always_inline u32 *get_buf_off(struct bufs_off_share *bufs_off, int buf_idx) {
  return bpf_map_lookup_elem(bufs_off, &buf_idx);
}
/*计算客体全路径*/
static __always_inline void *get_object_path(struct path *f_path, struct bufs_share *bufs, struct bufs_off_share *bufs_off) {
  bufs_t *path_buf = get_buf(bufs, PATH_BUFFER);
  if (path_buf == NULL)
    return 0;

  if (!prepend_path(f_path, path_buf, bufs_off))
    return 0;

  u32 *path_offset = get_buf_off(bufs_off, PATH_BUFFER);
  if (path_offset == NULL)
    return 0;

  void *path_ptr = &path_buf->buf[*path_offset];
  return path_ptr;
}
/*计算主体全路径*/
static __always_inline void *get_subject_path(struct task_struct *t, struct path *f_path, struct bufs_share *bufs, struct bufs_off_share *bufs_off) {
  struct file *file_p = get_task_file(t);
  if (file_p == NULL)
    return 0;

  bufs_t *src_buf = get_buf(bufs, PATH_BUFFER);
  if (src_buf == NULL)
    return 0;

  struct path f_src = BPF_CORE_READ(file_p, f_path);
  if (!prepend_path(&f_src, src_buf, bufs_off))
    return 0;

  u32 *src_offset = get_buf_off(bufs_off, PATH_BUFFER);
  if (src_offset == NULL)
    return 0;

  void *ptr = &src_buf->buf[*src_offset];
  return ptr;
}
/*发送安全日志*/
static void send_security_log(struct task_struct *task, char *object_path, char *subject_path, u32 event_id, u32 id,struct ringbuf_custom *rb) {
  sec_event_t *sec_event_info;
  sec_event_info = bpf_ringbuf_reserve(rb,sizeof(sec_event_t),0);
  if(!sec_event_info){
    //bpf_printk("file_protect: ringbuf apply for space failed,exit");
    return;
  }

  //pid ppid
  sec_event_info->pid = bpf_get_current_pid_tgid() >> 32;
  sec_event_info->ppid = get_task_ppid(task);
  //uid
  sec_event_info->uid = bpf_get_current_uid_gid();
  //module_id 各个特性的值固定，勒索病毒2，文件防护 1
  sec_event_info->module_id = id;
  //事件id,根据LSM hook点区分
  sec_event_info->event_id = event_id;
  //主体和客体
  bpf_probe_read(sec_event_info->source, MAX_STRING_SIZE, subject_path);
  if(object_path){
    bpf_probe_read(sec_event_info->path, MAX_STRING_SIZE, object_path);
  }

  //comm
  bpf_get_current_comm(&sec_event_info->comm,sizeof(sec_event_info->comm));

  //上传日志
  bpf_ringbuf_submit(sec_event_info,0);
}

static  __always_inline int strcmp(const char *x, const char *y)
{
        const char *a = x;
        const char *b = y;
#pragma unroll(MAX_STRING_SIZE)
        for (int i = 0; i < MAX_STRING_SIZE; i++){
                if (*a == '\0' || *b == '\0')
                        return *a - *b;
                a++;
                b++;
        }
        return 0;
}

static __always_inline int strlen_of_array(char* array_name, int array_size)
{
    const char* s = array_name;
    int i;
    for (i=0; i<array_size; ++i){
        if (*s == '\0')
            break;
        ++s;
    }
    return i;
}
//对比字符串，匹配创建文件名是.00abcdf.docx.开头
static  __always_inline int strncmp(const char *x,const unsigned char *y, unsigned int len)
{
        const char *a = x;
        const unsigned char *b = y;
        for (unsigned int i = 0; i < len; i++) {
                if (!*a && !*b)
                        return 0;
                if (*a != *b)
                        return 1;
                a++;
                b++;
        }
        return 0;
}

static __always_inline int ksec_strcmp(char *str1, char *str2)
{
        int i = 0;
        while(*str1 && *str2 && i < 128)
        {
                i++;
                if(*str1 != *str2)
                        return *str1 - *str2;
                str1++;
                str2++;
        }
        return *str1 - *str2;
}

//从dentry中获取全路径
static __always_inline struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
	return READ_KERN(dentry->d_parent);
}
static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
	return READ_KERN(dentry->d_name);
}
static __always_inline struct mm_struct *get_mm_from_task(struct task_struct *task)
{
	return READ_KERN(task->mm);
}
static __always_inline struct file *get_exe_file_from_mm(struct mm_struct *mm)
{
	return READ_KERN(mm->exe_file);
}
static __always_inline struct path get_path_from_file(struct file *file)
{
	return READ_KERN(file->f_path);
}

static __always_inline struct file *get_file_from_bprm(struct linux_binprm *bprm)
{
        return READ_KERN(bprm->file);
}

static __always_inline int get_pid_from_task(struct task_struct *t)
{
        return READ_KERN(t->pid);
}

static __always_inline int get_tid_from_task(struct task_struct *t)
{
        return READ_KERN(t->tgid);
}

#endif /* __SHARED_H */
