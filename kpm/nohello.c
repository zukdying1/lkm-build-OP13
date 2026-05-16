// SPDX-License-Identifier: GPL-2.0
/*
 * nohello - hide a given file from all system calls (arm64 Android / GKI)
 *
 * Uses KernelPatch hooks to intercept VFS operations and make the target file
 * appear as non-existent.  Identification is via the (inode, dev) pair.
 *
 * KPM version for KernelPatch
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <hook.h>
#include <syscall.h>
#include <kallsyms.h>
#include <linux/ptrace.h>

/* ---------- module parameter ---------- */
#define MAX_HIDE_TARGETS 16
#define MAX_DENY_UIDS 128
#define TARGET_PATHS_LEN 2048
#define TARGET_TEXT_LEN 256
#define UID_LIST_LEN 2048
#define ANDROID_USER_OFFSET 100000u
#define ANDROID_ISOLATED_START 99000u
#define ANDROID_ISOLATED_END 99999u

enum nohello_scope_mode {
	SCOPE_GLOBAL = 0,
	SCOPE_DENY,
};

/* Module metadata */
KPM_NAME("kpm-nohello");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Andrea-lyz");
KPM_DESCRIPTION("Hide a file by intercepting VFS operations via KernelPatch hooks");

/* Module parameters */
static char *target_path = "/data/local/tmp/nohello";
static char target_paths[TARGET_PATHS_LEN];
static bool hide_dirents = true;
static bool hide_isolated = true;
static char scope_mode[16] = "global";
static char deny_uids[UID_LIST_LEN];

/* system-unique target identifiers */
struct hidden_target {
	unsigned long long dev;
	unsigned long long ino;
	char path[TARGET_TEXT_LEN];
};

static struct hidden_target targets[MAX_HIDE_TARGETS];
static unsigned int target_count;
static enum nohello_scope_mode active_scope = SCOPE_GLOBAL;
static unsigned int deny_uid_list[MAX_DENY_UIDS];
static unsigned int deny_uid_count;

/* Function pointers for hooked functions */
static int (*orig_security_inode_permission)(struct inode *inode, int mask);
static int (*orig_security_inode_getattr)(const struct path *path);
static long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);

/* Hook chain structures */
static hook_chain_t *inode_perm_hook = NULL;
static hook_chain_t *inode_getattr_hook = NULL;
static hook_chain_t *getdents_hook = NULL;

/* ---------- helper ---------- */
static inline bool is_target_inode(const struct inode *inode)
{
	unsigned int i;

	if (!inode)
		return false;

	for (i = 0; i < target_count; i++) {
		if (inode->i_ino == targets[i].ino &&
		    inode->i_sb->s_dev == targets[i].dev)
			return true;
	}

	return false;
}

static inline bool is_target_ino(unsigned long long ino)
{
	unsigned int i;

	for (i = 0; i < target_count; i++) {
		if (ino == targets[i].ino)
			return true;
	}

	return false;
}

static inline bool is_denied_uid(unsigned int uid)
{
	unsigned int i;

	for (i = 0; i < deny_uid_count; i++) {
		if (uid == deny_uid_list[i])
			return true;
	}

	return false;
}

static inline bool is_android_isolated_uid(unsigned int uid)
{
	unsigned int app_id = uid % ANDROID_USER_OFFSET;

	return app_id >= ANDROID_ISOLATED_START &&
	       app_id <= ANDROID_ISOLATED_END;
}

static inline bool should_hide_for_current(void)
{
	unsigned int uid, euid, fsuid;

	if (active_scope == SCOPE_GLOBAL)
		return true;

	uid = current_uid();
	euid = current_euid();
	fsuid = current_fsuid();

	if (hide_isolated &&
	    (is_android_isolated_uid(uid) ||
	     is_android_isolated_uid(euid) ||
	     is_android_isolated_uid(fsuid)))
		return true;

	return is_denied_uid(uid) || is_denied_uid(euid) ||
	       is_denied_uid(fsuid);
}

static int parse_scope_mode(void)
{
	if (!strcmp(scope_mode, "global")) {
		active_scope = SCOPE_GLOBAL;
		return 0;
	}

	if (!strcmp(scope_mode, "deny")) {
		active_scope = SCOPE_DENY;
		return 0;
	}

	pr_err("nohello: unsupported scope_mode=%s\n", scope_mode);
	return -1;
}

static int add_deny_uid(unsigned int uid)
{
	if (deny_uid_count >= MAX_DENY_UIDS) {
		pr_warn("nohello: too many deny UIDs, skip %u\n", uid);
		return -1;
	}

	if (is_denied_uid(uid))
		return 0;

	deny_uid_list[deny_uid_count++] = uid;
	pr_info("nohello: deny_uid[%u]=%u\n", deny_uid_count - 1, uid);
	return 0;
}

static int parse_deny_uids(void)
{
	char *buf, *cursor, *item;
	int ret = 0;

	if (!deny_uids[0])
		return 0;

	buf = kstrdup(deny_uids);
	if (!buf)
		return -1;

	cursor = buf;
	while ((item = strsep(&cursor, ",")) != NULL) {
		unsigned int uid;

		item = strim(item);
		if (!*item)
			continue;

		ret = kstrtouint(item, 10, &uid);
		if (ret) {
			pr_warn("nohello: invalid deny uid %s\n", item);
			continue;
		}

		add_deny_uid((unsigned int)uid);
	}

	kfree(buf);

	if (active_scope == SCOPE_DENY && !deny_uid_count)
		pr_warn("nohello: scope_mode=deny but deny_uids is empty\n");

	return 0;
}

static int add_target_path(const char *path_name)
{
	struct path path;
	struct inode *inode;
	int ret;

	if (target_count >= MAX_HIDE_TARGETS) {
		pr_warn("nohello: too many targets, skip %s\n", path_name);
		return -1;
	}

	ret = kern_path(path_name, 0, &path);
	if (ret) {
		pr_warn("nohello: %s not found (err=%d), skip\n", path_name,
			ret);
		return ret;
	}

	inode = d_inode(path.dentry);
	targets[target_count].ino = inode->i_ino;
	targets[target_count].dev = inode->i_sb->s_dev;
	strscpy(targets[target_count].path, path_name,
		sizeof(targets[target_count].path));
	pr_info("nohello: target[%u] %s ino=%llu dev=%llu\n",
		target_count, path_name, targets[target_count].ino,
		targets[target_count].dev);
	target_count++;
	path_put(&path);

	return 0;
}

static int resolve_target_paths(const char *paths)
{
	char *buf, *cursor, *item;
	int ret = -1;

	buf = kstrdup(paths);
	if (!buf)
		return -1;

	cursor = buf;
	while ((item = strsep(&cursor, ",")) != NULL) {
		item = strim(item);
		if (!*item)
			continue;

		ret = add_target_path(item);
		if (ret && target_count == 0)
			continue;
	}

	kfree(buf);

	if (!target_count)
		return ret;

	return 0;
}

/* ---------- Hook callbacks ---------- */
static void inode_perm_before(hook_fargs2_t *fargs, void *udata)
{
	struct inode *inode = (struct inode *)fargs->arg0;
	
	if (should_hide_for_current() && is_target_inode(inode)) {
		fargs->skip_origin = 1;
		fargs->ret = -ENOENT;
	}
}

static void inode_getattr_before(hook_fargs2_t *fargs, void *udata)
{
	struct path *path = (struct path *)fargs->arg0;
	struct inode *inode = d_inode(path->dentry);
	
	if (should_hide_for_current() && is_target_inode(inode)) {
		fargs->skip_origin = 1;
		fargs->ret = -ENOENT;
	}
}

static void getdents_before(hook_fargs3_t *fargs, void *udata)
{
	unsigned int fd = (unsigned int)fargs->arg0;
	struct linux_dirent64 *dirent = (struct linux_dirent64 *)fargs->arg1;
	unsigned int count = (unsigned int)fargs->arg2;
	
	/* We'll handle the filtering in the after callback */
}

static void getdents_after(hook_fargs3_t *fargs, void *udata)
{
	long ret = fargs->ret;
	struct linux_dirent64 *dirent = (struct linux_dirent64 *)fargs->arg1;
	struct linux_dirent64 *kbuf, *prev, *cur;
	long bpos, new_len;
	const size_t hdr_off = offsetof(struct linux_dirent64, d_name);
	const size_t min_reclen = offsetof(struct linux_dirent64, d_name) + 1;
	bool modified = false;

	if (ret <= 0 || !should_hide_for_current() || !dirent)
		return;

	/* Allocate kernel buffer to copy dirent data */
	kbuf = kmalloc(ret, GFP_KERNEL);
	if (!kbuf)
		return;

	if (copy_from_user(kbuf, dirent, ret))
		goto out;

	prev = NULL;
	bpos = 0;
	new_len = ret;

	while (bpos + (long)hdr_off < new_len) {
		unsigned short reclen;

		cur = (struct linux_dirent64 *)((char *)kbuf + bpos);
		reclen = cur->d_reclen;

		if (reclen < min_reclen || reclen > new_len - bpos)
			break;

		if (is_target_ino(cur->d_ino)) {
			modified = true;
			if (prev) {
				if ((unsigned int)prev->d_reclen + reclen <=
				    65535u) {
					prev->d_reclen += reclen;
					bpos += reclen;
					continue;
				}
			}

			new_len -= reclen;
			if (new_len > bpos)
				memmove(cur, (char *)cur + reclen,
					new_len - bpos);
			continue;
		}

		prev = cur;
		bpos += reclen;
	}

	if (modified) {
		if (copy_to_user(dirent, kbuf, new_len))
			pr_warn_ratelimited("nohello: copy_to_user failed, "
					    "directory may leak\n");
		else
			fargs->ret = new_len;
	}

out:
	kfree(kbuf);
}

/* ---------- module init / exit ---------- */
static long nohello_init(const char *args, const char *event, void *reserved)
{
	const char *paths = target_paths[0] ? target_paths : target_path;
	int ret;
	void *func;

	pr_info("nohello: initializing, event: %s, args: %s\n", event, args ? args : "none");

	ret = parse_scope_mode();
	if (ret)
		return ret;

	ret = parse_deny_uids();
	if (ret)
		return ret;

	ret = resolve_target_paths(paths);
	if (ret) {
		pr_err("nohello: no valid targets (err=%d)\n", ret);
		return ret;
	}

	/* Hook security_inode_permission */
	func = (void *)kallsyms_lookup_name("security_inode_permission");
	if (func) {
		ret = hook_wrap(func, 2, inode_perm_before, NULL, NULL);
		if (ret) {
			pr_err("nohello: hook_wrap(security_inode_permission) failed: %d\n", ret);
		} else {
			pr_info("nohello: hooked security_inode_permission\n");
		}
	} else {
		pr_warn("nohello: security_inode_permission not found\n");
	}

	/* Hook security_inode_getattr */
	func = (void *)kallsyms_lookup_name("security_inode_getattr");
	if (func) {
		ret = hook_wrap(func, 2, inode_getattr_before, NULL, NULL);
		if (ret) {
			pr_err("nohello: hook_wrap(security_inode_getattr) failed: %d\n", ret);
		} else {
			pr_info("nohello: hooked security_inode_getattr\n");
		}
	} else {
		pr_warn("nohello: security_inode_getattr not found\n");
	}

	if (hide_dirents) {
		/* Hook __arm64_sys_getdents64 */
		func = (void *)kallsyms_lookup_name("__arm64_sys_getdents64");
		if (func) {
			ret = hook_wrap(func, 3, getdents_before, getdents_after, NULL);
			if (ret) {
				pr_warn("nohello: hook_wrap(__arm64_sys_getdents64) failed: %d; "
					"file visible in listings but still hidden from direct access\n",
					ret);
			} else {
				pr_info("nohello: hooked __arm64_sys_getdents64\n");
			}
		} else {
			pr_warn("nohello: __arm64_sys_getdents64 not found\n");
		}
	} else {
		pr_info("nohello: hide_dirents=0, directory listings are not filtered\n");
	}

	pr_info("nohello: loaded -- %u target(s) hidden, scope=%s, "
		"deny_uid_count=%u hide_isolated=%d\n",
		target_count, scope_mode, deny_uid_count, hide_isolated);
	return 0;
}

static long nohello_exit(void *reserved)
{
	void *func;

	/* Unhook all functions */
	func = (void *)kallsyms_lookup_name("security_inode_permission");
	if (func)
		hook_unwrap_remove(func, inode_perm_before, NULL, 1);

	func = (void *)kallsyms_lookup_name("security_inode_getattr");
	if (func)
		hook_unwrap_remove(func, inode_getattr_before, NULL, 1);

	if (hide_dirents) {
		func = (void *)kallsyms_lookup_name("__arm64_sys_getdents64");
		if (func)
			hook_unwrap_remove(func, getdents_before, getdents_after, 1);
	}

	pr_info("nohello: unloaded -- %u target(s) visible again\n", target_count);
	return 0;
}

static long nohello_control(const char *ctl_args, char __user *out_msg, int outlen)
{
	char response[256];
	
	if (!ctl_args) {
		snprintf(response, sizeof(response), "nohello: %u target(s) hidden, scope=%s", 
			 target_count, scope_mode);
	} else if (!strcmp(ctl_args, "status")) {
		snprintf(response, sizeof(response), "nohello: %u target(s) hidden, scope=%s, "
			 "deny_uid_count=%u hide_isolated=%d",
			 target_count, scope_mode, deny_uid_count, hide_isolated);
	} else if (!strcmp(ctl_args, "targets")) {
		int i, len = 0;
		len += snprintf(response + len, sizeof(response) - len, "targets: ");
		for (i = 0; i < target_count; i++) {
			len += snprintf(response + len, sizeof(response) - len, "%s%s", 
					i > 0 ? "," : "", targets[i].path);
		}
	} else {
		snprintf(response, sizeof(response), "nohello: unknown command '%s'", ctl_args);
	}
	
	compat_copy_to_user(out_msg, response, sizeof(response));
	return 0;
}

KPM_INIT(nohello_init);
KPM_EXIT(nohello_exit);
KPM_CTL0(nohello_control);