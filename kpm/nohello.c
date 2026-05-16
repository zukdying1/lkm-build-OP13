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
#include <kallsyms.h>

/* ---------- module parameter ---------- */
#define MAX_HIDE_TARGETS 16
#define MAX_DENY_UIDS 128
#define TARGET_PATHS_LEN 2048
#define TARGET_TEXT_LEN 256
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
static char target_paths[TARGET_PATHS_LEN] = {0};
static bool hide_dirents = true;
static bool hide_isolated = true;
static char scope_mode[16] = "global";
static char deny_uids[TARGET_PATHS_LEN] = {0};

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

/* Original function pointers */
static void *orig_security_inode_permission = NULL;
static void *orig_security_inode_getattr = NULL;

/* ---------- helper ---------- */
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
	unsigned int uid;

	if (active_scope == SCOPE_GLOBAL)
		return true;

	uid = current_uid();

	if (hide_isolated && is_android_isolated_uid(uid))
		return true;

	return is_denied_uid(uid);
}

static void add_deny_uid(unsigned int uid)
{
	if (deny_uid_count >= MAX_DENY_UIDS)
		return;

	if (is_denied_uid(uid))
		return;

	deny_uid_list[deny_uid_count++] = uid;
}

static void parse_deny_uids_string(const char *uids_str)
{
	char buf[TARGET_PATHS_LEN];
	char *cursor, *item;
	unsigned int uid;

	if (!uids_str || !uids_str[0])
		return;

	strscpy(buf, uids_str, sizeof(buf));
	cursor = buf;

	while ((item = strsep(&cursor, ",")) != NULL) {
		item = strim(item);
		if (!*item)
			continue;

		uid = 0;
		while (*item >= '0' && *item <= '9') {
			uid = uid * 10 + (*item - '0');
			item++;
		}
		add_deny_uid(uid);
	}
}

static void add_target_path(const char *path_name)
{
	if (target_count >= MAX_HIDE_TARGETS)
		return;

	strscpy(targets[target_count].path, path_name,
		sizeof(targets[target_count].path));
	targets[target_count].ino = 0;
	targets[target_count].dev = 0;
	target_count++;
}

static void parse_target_paths_string(const char *paths_str)
{
	char buf[TARGET_PATHS_LEN];
	char *cursor, *item;

	if (!paths_str || !paths_str[0])
		return;

	strscpy(buf, paths_str, sizeof(buf));
	cursor = buf;

	while ((item = strsep(&cursor, ",")) != NULL) {
		item = strim(item);
		if (!*item)
			continue;
		add_target_path(item);
	}
}

/* ---------- Hook callbacks ---------- */
static void inode_perm_before(hook_fargs2_t *fargs, void *udata)
{
	struct inode *inode = (struct inode *)fargs->arg0;

	if (!inode || !should_hide_for_current())
		return;

	if (is_target_ino(inode->i_ino)) {
		fargs->skip_origin = 1;
		fargs->ret = (unsigned long)-2; /* -ENOENT */
	}
}

static void inode_getattr_before(hook_fargs2_t *fargs, void *udata)
{
	struct path *path = (struct path *)fargs->arg0;
	struct inode *inode;

	if (!path || !path->dentry)
		return;

	inode = path->dentry->d_inode;
	if (!inode || !should_hide_for_current())
		return;

	if (is_target_ino(inode->i_ino)) {
		fargs->skip_origin = 1;
		fargs->ret = (unsigned long)-2; /* -ENOENT */
	}
}

/* ---------- module init / exit ---------- */
static long nohello_init(const char *args, const char *event, void *reserved)
{
	hook_err_t err;
	void *func;

	logkd("nohello kpm: initializing, event: %s, args: %s\n",
	      event, args ? args : "none");

	/* Parse scope mode */
	if (scope_mode[0] == 'd')
		active_scope = SCOPE_DENY;
	else
		active_scope = SCOPE_GLOBAL;

	/* Parse deny UIDs */
	parse_deny_uids_string(deny_uids);

	/* Parse target paths */
	if (target_paths[0])
		parse_target_paths_string(target_paths);
	else
		parse_target_paths_string(target_path);

	if (target_count == 0) {
		logkd("nohello kpm: no targets configured\n");
		return 0;
	}

	logkd("nohello kpm: %u target(s), scope=%s, deny_uid_count=%u\n",
	      target_count, scope_mode, deny_uid_count);

	/* Hook security_inode_permission */
	func = (void *)kallsyms_lookup_name("security_inode_permission");
	if (func) {
		err = hook_wrap2(func, inode_perm_before, 0, 0);
		if (err) {
			logkd("nohello kpm: hook security_inode_permission failed: %d\n", err);
		} else {
			orig_security_inode_permission = func;
			logkd("nohello kpm: hooked security_inode_permission\n");
		}
	}

	/* Hook security_inode_getattr */
	func = (void *)kallsyms_lookup_name("security_inode_getattr");
	if (func) {
		err = hook_wrap2(func, inode_getattr_before, 0, 0);
		if (err) {
			logkd("nohello kpm: hook security_inode_getattr failed: %d\n", err);
		} else {
			orig_security_inode_getattr = func;
			logkd("nohello kpm: hooked security_inode_getattr\n");
		}
	}

	logkd("nohello kpm: loaded successfully\n");
	return 0;
}

static long nohello_exit(void *reserved)
{
	if (orig_security_inode_permission) {
		unhook(orig_security_inode_permission);
		orig_security_inode_permission = NULL;
	}

	if (orig_security_inode_getattr) {
		unhook(orig_security_inode_getattr);
		orig_security_inode_getattr = NULL;
	}

	logkd("nohello kpm: unloaded\n");
	return 0;
}

static long nohello_control(const char *ctl_args, char __user *out_msg, int outlen)
{
	char response[256];

	if (!ctl_args || !ctl_args[0]) {
		strscpy(response, "nohello kpm: use 'status' or 'targets'", sizeof(response));
	} else if (!strcmp(ctl_args, "status")) {
		snprintf(response, sizeof(response),
			 "targets=%u scope=%s deny_uids=%u",
			 target_count, scope_mode, deny_uid_count);
	} else {
		strscpy(response, "nohello kpm: unknown command", sizeof(response));
	}

	compat_copy_to_user(out_msg, response, sizeof(response));
	return 0;
}

KPM_INIT(nohello_init);
KPM_EXIT(nohello_exit);
KPM_CTL0(nohello_control);
