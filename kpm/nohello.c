// SPDX-License-Identifier: GPL-2.0
/*
 * nohello KPM - hide file by path comparison
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/dcache.h>

KPM_NAME("kpm-nohello");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Andrea-lyz");
KPM_DESCRIPTION("Hide a file by intercepting VFS operations");

#define TARGET_PATH_LEN 256

static char target_path[TARGET_PATH_LEN] = "/data/local/tmp/nohello";
static void *hooked_inode_permission = NULL;
static void *hooked_inode_getattr = NULL;

static void inode_perm_before(hook_fargs2_t *fargs, void *udata)
{
    struct inode *inode = (struct inode *)fargs->arg0;
    struct path path;
    char buf[256];
    char *p;

    if (!inode)
        return;

    /* We can't access inode->i_ino directly, so we use a different approach */
    /* For now, just log that the hook was called */
    /* In a real implementation, we would need to use kallsyms to get inode offsets */
}

static void inode_getattr_before(hook_fargs2_t *fargs, void *udata)
{
    struct path *path = (struct path *)fargs->arg0;
    char buf[256];
    char *p;

    if (!path)
        return;

    /* Use d_path to get the path string */
    p = d_path(path, buf, sizeof(buf));
    if (p && !IS_ERR(p)) {
        if (strcmp(p, target_path) == 0) {
            fargs->skip_origin = 1;
            fargs->ret = (unsigned long)-2; /* -ENOENT */
            logkd("nohello kpm: hiding %s\n", p);
        }
    }
}

static long nohello_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;
    void *func;

    logkd("nohello kpm: init, target: %s\n", target_path);

    /* Hook security_inode_permission */
    func = (void *)kallsyms_lookup_name("security_inode_permission");
    if (func) {
        err = hook_wrap2(func, inode_perm_before, 0, 0);
        if (err) {
            logkd("nohello kpm: hook security_inode_permission failed: %d\n", err);
        } else {
            hooked_inode_permission = func;
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
            hooked_inode_getattr = func;
            logkd("nohello kpm: hooked security_inode_getattr\n");
        }
    }

    return 0;
}

static long nohello_exit(void *reserved)
{
    if (hooked_inode_permission) {
        unhook(hooked_inode_permission);
        hooked_inode_permission = NULL;
    }
    if (hooked_inode_getattr) {
        unhook(hooked_inode_getattr);
        hooked_inode_getattr = NULL;
    }
    logkd("nohello kpm: exit\n");
    return 0;
}

static long nohello_control(const char *ctl_args, char *out_msg, int outlen)
{
    logkd("nohello kpm: control\n");
    return 0;
}

KPM_INIT(nohello_init);
KPM_EXIT(nohello_exit);
KPM_CTL0(nohello_control);
