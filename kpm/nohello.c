// SPDX-License-Identifier: GPL-2.0
/*
 * nohello KPM - minimal test version
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <linux/string.h>

KPM_NAME("kpm-nohello");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Andrea-lyz");
KPM_DESCRIPTION("Hide a file by intercepting VFS operations");

static long nohello_init(const char *args, const char *event, void *reserved)
{
    pr_info("nohello kpm: init\n");
    return 0;
}

static long nohello_exit(void *reserved)
{
    pr_info("nohello kpm: exit\n");
    return 0;
}

static long nohello_control(const char *ctl_args, char *out_msg, int outlen)
{
    pr_info("nohello kpm: control\n");
    return 0;
}

KPM_INIT(nohello_init);
KPM_EXIT(nohello_exit);
KPM_CTL0(nohello_control);
