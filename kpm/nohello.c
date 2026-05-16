// SPDX-License-Identifier: GPL-2.0
/*
 * nohello KPM - test hook
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("kpm-nohello");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Andrea-lyz");
KPM_DESCRIPTION("Hide a file by intercepting VFS operations");

static void *hooked_func = NULL;

static void before_hook(hook_fargs2_t *fargs, void *udata)
{
    logkd("nohello kpm: before hook called\n");
}

static long nohello_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;
    void *func;

    logkd("nohello kpm: init\n");

    func = (void *)kallsyms_lookup_name("security_inode_permission");
    if (func) {
        err = hook_wrap2(func, before_hook, 0, 0);
        if (err) {
            logkd("nohello kpm: hook failed: %d\n", err);
        } else {
            hooked_func = func;
            logkd("nohello kpm: hook success\n");
        }
    } else {
        logkd("nohello kpm: security_inode_permission not found\n");
    }

    return 0;
}

static long nohello_exit(void *reserved)
{
    if (hooked_func) {
        unhook(hooked_func);
        hooked_func = NULL;
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
