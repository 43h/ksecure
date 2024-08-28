// +build ignore
/* SPDX-License-Identifier: Apache-2.0    */
/* Copyright 2024 Authors of IEIT SYSTEMS. */

#include "shared_ransomware.h"

SEC("lsm/inode_unlink")
int BPF_PROG(ransom_unlink, struct path *dir, struct dentry *dentry) { // check if ret code available
  struct path f_path;
  f_path.dentry = dentry;
  f_path.mnt = BPF_CORE_READ(dir, mnt);
  return match_and_enforce_path_ransom_hooks( &f_path, dpath, _SYS_UNLINK);
}

SEC("lsm/file_open")
int BPF_PROG(ransom_file_open, struct file *file) { // check if ret code available

  if(!(file->f_mode & (MODE_WRITE | MODE_PWRITE | MODE_APPEND)))
  {
    //在勒索中，如果不是写操作就不使用file_open控制
    return 0;
  }

  struct path f_path = BPF_CORE_READ(file, f_path);
  return match_and_enforce_path_ransom_hooks(&f_path, dfileread, _SYS_OPEN);
}

SEC("lsm/inode_rename")
int BPF_PROG(ransom_rename_old, struct path *old_dir,
             struct dentry *old_dentry) {
  struct path f_path;
  f_path.dentry = old_dentry;
  f_path.mnt = BPF_CORE_READ(old_dir, mnt);
  return match_and_enforce_path_ransom_hooks(&f_path, dpath ,_SYS_RENAME);
}

SEC("lsm/inode_rename")
int BPF_PROG(ransom_rename_new, struct path *old_dir,
             struct dentry *old_dentry, struct path *new_dir,
             struct dentry *new_dentry) {
  struct path f_path;
  f_path.dentry = new_dentry;
  f_path.mnt = BPF_CORE_READ(new_dir, mnt);
  return match_and_enforce_path_ransom_hooks(&f_path, dpath, _SYS_RENAME);
}
