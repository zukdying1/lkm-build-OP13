// SPDX-License-Identifier: GPL-2.0
/*
 * nohello - hide a given file from all system calls (arm64 Android / GKI)
 *
 * Uses KernelPatch hooks to intercept VFS operations and make the target file
 * appear as non-existent.  Identification is via the inode number.
 *
 * KPM version for KernelPatch
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/string.h>

/* ---------- module parameter ---------- */
#define MAX_HIDE_TARGETS 16
#define TARGET_PATHS_LEN 2048
#define TARGET_TEXT_LEN 256

/* Module metadata */
KPM_NAME("kpm-nohello");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Andrea-lyz");
KPM_DESCRIPTION("Hide a file by intercepting VFS operations via KernelPatch hooks");

/* Module parameters */
static char target_paths[TARGET_PATHS_LEN] = "/data/local/tmp/nohello";

/* system-unique target identifiers */
struct hidden_target {
    unsigned long long ino;
    char path[TARGET_TEXT_LEN];
};

static struct hidden_target targets[MAX_HIDE_TARGETS];
static unsigned int target_count;

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

/* ---------- Hook callbacks ---------- */
static void inode_perm_before(hook_fargs2_t *fargs, void *udata)
{
    struct inode *inode = (struct inode *)fargs->arg0;

    if (!inode)
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
    if (!inode)
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

    /* For now, just set a dummy target to test compilation */
    target_count = 1;
    strscpy(targets[0].path, target_paths, sizeof(targets[0].path));
    targets[0].ino = 0;

    logkd("nohello kpm: target path: %s\n", targets[0].path);

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
    char response[64] = "nohello kpm: ok";
    compat_copy_to_user(out_msg, response, sizeof(response));
    return 0;
}

KPM_INIT(nohello_init);
KPM_EXIT(nohello_exit);
KPM_CTL0(nohello_control);
