/*
 * Copyright (C) 2017 yoh2
 *
 * yes.ko is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licence as published by the
 * Free Software Foundation, version 2 of the License, or (at your option)
 * any later version.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/mount.h>
//#include <linux/exportfs.h>
#include <linux/file.h>

#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

#define YESFS_SUPER_MAGIC 0x7965730a
#define BOGO_DIRENT_SIZE  20
#define MAX_MSG_BUF       PAGE_SIZE

struct yesfs_file_info {
	size_t msg_buf_size;
	char *msg_buf;
};

static ssize_t yesfs_copy_to_user(char __user *dst, const struct yesfs_file_info *info, size_t count, loff_t offset)
{
	off_t first_buf_offset = offset % info->msg_buf_size;
	ssize_t total_read = 0;
	if (first_buf_offset > 0) {
		size_t n = (first_buf_offset + count > info->msg_buf_size)
			? info->msg_buf_size - first_buf_offset
			: count;
		if(copy_to_user(dst, info->msg_buf + first_buf_offset, n)) {
			return -EFAULT;
		}
		total_read += n;
	}

	while (total_read + info->msg_buf_size < count) {
		if(copy_to_user(dst + total_read, info->msg_buf, info->msg_buf_size))
		{
			return -EFAULT;
		}
		total_read += info->msg_buf_size;
	}

	if (total_read < count) {
		if (copy_to_user(dst + total_read, info->msg_buf, count - total_read)) {
			return -EFAULT;
		}
	}

	return count;
}

static ssize_t yesfs_read(
	struct file *file, char __user *buf,
	size_t count, loff_t *ppos)
{
	ssize_t read_size;

	read_size = yesfs_copy_to_user(buf, file->private_data, count, *ppos);
	*ppos += read_size;
	return read_size;
}

static ssize_t yesfs_write(
	struct file *file, const char __user *buf,
	size_t count, loff_t *ppos)
{
	return count;
}

static int yesfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	char *path_buf;
	char *path;
	size_t path_len;
	struct yesfs_file_info *info;
	size_t nr_repeats;
	size_t msg_buf_size;
	size_t i;

	path_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if(path_buf == NULL) {
		err = -ENOMEM;
		goto err_alloc_path_buf;
	}

	//path = d_path(&file->f_path, path_buf, PATH_MAX);
	path = dentry_path_raw(file->f_path.dentry, path_buf, PATH_MAX);
	//path = simple_dname(file->f_path.dentry, path_buf, PATH_MAX);
	if(IS_ERR(path)) {
		err = PTR_ERR(path);
		goto err_path;
	}
	printk(KERN_DEBUG "yesfs: yesfs_open called: path = %s\n", path);

	if(path[0] == '/') {
		path++;
	}
	path_len = strlen(path);
	nr_repeats = (path_len + 1 >= MAX_MSG_BUF) ? 1 : (MAX_MSG_BUF / (path_len + 1)); // +1 : for '\n'
	msg_buf_size = nr_repeats * (path_len + 1);
	info = kzalloc(sizeof(struct yesfs_file_info), GFP_KERNEL);
	if(info == NULL) {
		err = -ENOMEM;
		goto err_alloc_file_info;
	}
	info->msg_buf = kzalloc(msg_buf_size, GFP_KERNEL);
	if(info->msg_buf == NULL) {
		err = -ENOMEM;
		goto err_alloc_buf;
	}
	info->msg_buf_size = msg_buf_size;
	for(i = 0; i < msg_buf_size; i += path_len + 1) {
		memcpy(info->msg_buf + i, path, path_len);
		info->msg_buf[i + path_len] = '\n';
	}
	file->private_data = info;
	kfree(path_buf);
	return 0;

err_alloc_buf:
	kfree(info);
err_alloc_file_info:
err_path:
	kfree(path_buf);
err_alloc_path_buf:
	return err;
}

static int yesfs_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct file_operations yesfs_file_operations = {
	.llseek  = no_seek_end_llseek,
	.read    = yesfs_read,
	.write   = yesfs_write,
	.open    = yesfs_open,
	.release = yesfs_release,
};

static int yesfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	generic_fillattr(dentry->d_inode, stat);
	return 0;
}

static int yesfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	return 0;
}

static const struct inode_operations yesfs_inode_operations = {
	.getattr = yesfs_getattr,
	.setattr = yesfs_setattr,
};

static struct inode *yesfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode);

static int yesfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = 0;
	struct inode *inode = yesfs_get_inode(dir->i_sb, dir, mode);
	if(inode == NULL) {
		err = -ENOSPC;
		goto err_get_inode;
	}
	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_ctime = dir->i_mtime = current_time(dir);
	d_instantiate(dentry, inode);
	dget(dentry);
	return 0;

err_get_inode:
	return err;
}

static int yesfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	return yesfs_mknod(dir, dentry, mode | S_IFREG);
}

static int yesfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	dir->i_size += BOGO_DIRENT_SIZE;
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
	inc_nlink(inode);
	ihold(inode);
	dget(dentry);
	d_instantiate(dentry, inode);
	return 0;
}

static int yesfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	dir->i_size -= BOGO_DIRENT_SIZE;
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
	drop_nlink(inode);
	dput(dentry);
	return 0;
}

static int yesfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = yesfs_mknod(dir, dentry, mode | S_IFDIR);
	if(err) {
		return err;
	}
	inc_nlink(dir);
	return 0;
}

static int yesfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!simple_empty(dentry)) {
		return -ENOTEMPTY;
	}
	drop_nlink(d_inode(dentry));
	drop_nlink(dir);
	return yesfs_unlink(dir, dentry);
}

static const struct inode_operations yesfs_dir_inode_operations = {
	.create = yesfs_create,
	.lookup = simple_lookup,
	.link   = yesfs_link,
	.unlink = yesfs_unlink,
	.mkdir  = yesfs_mkdir,
	.rmdir  = yesfs_rmdir,
};

struct yesfs_sb_info {
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	unsigned long next_ino;
};

struct yesfs_inode_info {
	struct inode vfs_inode;
};

static inline struct yesfs_inode_info *YESFS_I(struct inode *inode)
{
	return container_of(inode, struct yesfs_inode_info, vfs_inode);
}

static inline struct yesfs_sb_info *YESFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static void yesfs_init_inode(void *foo)
{
	struct yesfs_inode_info *info = (struct yesfs_inode_info *)foo;
	inode_init_once(&info->vfs_inode);
}

static struct kmem_cache *yesfs_inode_cachep;

static int yesfs_init_inodecache(void)
{
	yesfs_inode_cachep = kmem_cache_create("yesfs_inode_cache",
		sizeof(struct yesfs_inode_info),
		0, SLAB_PANIC, yesfs_init_inode);
	if(yesfs_inode_cachep == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static void yesfs_destroy_inodecache(void)
{
	rcu_barrier();
	kmem_cache_destroy(yesfs_inode_cachep);
}

static struct inode *yesfs_alloc_inode(struct super_block *sb)
{
	return kmem_cache_alloc(yesfs_inode_cachep, GFP_NOFS);
}

static void yesfs_i_callback(struct rcu_head *head)
{
	struct inode *inode;
	inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(yesfs_inode_cachep, YESFS_I(inode));
}

static void yesfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, yesfs_i_callback);
}

static void yesfs_evict_inode(struct inode *inode)
{
	clear_inode(inode);
}

static void yesfs_put_super(struct super_block *sb)
{
	struct yesfs_sb_info *sbinfo = YESFS_SB(sb);
	kfree(sbinfo);
	sb->s_fs_info = NULL;
}

static int yesfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	buf->f_type = YESFS_SUPER_MAGIC;
	buf->f_bsize = PAGE_SIZE;
	buf->f_blocks = 0;
	buf->f_bavail = 0;
	buf->f_bfree = 0;
	buf->f_namelen = NAME_MAX;

	return 0;
}

static int yesfs_remount(struct super_block *sb, int *flags, char *data)
{
	return 0;
}

static struct inode *yesfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode)
{
	int err = 0;
	struct yesfs_sb_info *sbinfo = YESFS_SB(sb);
	struct inode *inode;

	inode = new_inode(sb);
	if(inode == NULL) {
		err = -ENOMEM;
		goto err_new_inode;
	}

	inode->i_ino = sbinfo->next_ino++;
	inode_init_owner(inode, dir, mode);
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_generation = get_seconds();

	switch(mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &yesfs_inode_operations;
		inode->i_fop = &yesfs_file_operations;
		break;

	case S_IFDIR:
		inc_nlink(inode);
		inode->i_size = 2 * BOGO_DIRENT_SIZE;
		inode->i_op = &yesfs_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		break;

	default:
		err = -EOPNOTSUPP;
		goto err_mode;
	}

	return inode;
err_mode:
	free_inode_nonrcu(inode);
err_new_inode:
	return ERR_PTR(err);
}

static const struct super_operations yesfs_ops = {
	.alloc_inode    = yesfs_alloc_inode,
	.destroy_inode  = yesfs_destroy_inode,
	//.write_inode    = NULL,
	.evict_inode    = yesfs_evict_inode,
	.drop_inode     = generic_delete_inode,
	.put_super      = yesfs_put_super,
	.statfs         = yesfs_statfs,
	.remount_fs     = yesfs_remount,
	.show_options   = generic_show_options,
};

static int yesfs_fill_super(struct super_block *sb, void *data, int silent)
{
	int err = 0;
	struct yesfs_sb_info *sbinfo;
	struct inode *inode;

	sbinfo = kzalloc(max((int)sizeof(struct yesfs_sb_info), L1_CACHE_BYTES), GFP_KERNEL);
	if(sbinfo == NULL) {
		err = -ENOMEM;
		goto err_alloc_sbinfo;
	}

	sbinfo->mode = S_IRWXUGO;
	sbinfo->uid = current_fsuid();
	sbinfo->gid = current_fsgid();
	sbinfo->next_ino = 1;
	sb->s_fs_info = sbinfo;

	//sb->s_export_op = &yesfs_export_ops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = YESFS_SUPER_MAGIC;
	sb->s_op = &yesfs_ops;
	sb->s_time_gran = 1;

	inode = yesfs_get_inode(sb, NULL, S_IFDIR | sbinfo->mode);
	if(IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto err_get_inode;
	}
	sb->s_root = d_make_root(inode);
	if (sb->s_root == NULL) {
		err = -ENOMEM;
		goto err_make_root;
	}

	return 0;

err_make_root:
	free_inode_nonrcu(inode);
err_get_inode:
	yesfs_put_super(sb);
err_alloc_sbinfo:
	return err;
}

static struct dentry *yesfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, yesfs_fill_super);
}

static struct file_system_type yesfs_fs_type = {
	.owner    = THIS_MODULE,
	.name     = "yesfs",
	.mount    = yesfs_mount,
	.kill_sb  = kill_litter_super,
	.fs_flags = FS_USERNS_MOUNT,
};


static int __init yesfs_init(void)
{
	int err = 0;

	if(yesfs_inode_cachep) {
		return 0;
	}

	err = yesfs_init_inodecache();
	if(err) {
		printk(KERN_ALERT "yesfs: failed to allocate inode cache.\n");
		goto err_init_inodecache;
	}

	err = register_filesystem(&yesfs_fs_type);
	if(err) {
		printk(KERN_ALERT "yesfs: failed to register.\n");
		goto err_register_fs;
	}
	return 0;

err_register_fs:
	yesfs_destroy_inodecache();
err_init_inodecache:
	return err;
}

static void __exit yesfs_cleanup(void)
{
	unregister_filesystem(&yesfs_fs_type);
	yesfs_destroy_inodecache();
}

module_init(yesfs_init);
module_exit(yesfs_cleanup);
