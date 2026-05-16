// SPDX-License-Identifier: GPL-2.0
/*
 * nohello KPM - OnePlus SM8650 适配版
 * 支持多路径隐藏，通过参数配置
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
#include <linux/err.h>

KPM_NAME("kpm-nohello");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Andrea-lyz");
KPM_DESCRIPTION("Hide files by intercepting VFS operations - OnePlus SM8650 Edition");

#define MAX_TARGETS 16
#define TARGET_PATH_LEN 256
#define PATHS_BUFFER_LEN 2048

/* 目标路径结构 */
struct target_path {
    char path[TARGET_PATH_LEN];
    int len;
};

/* 模块状态 */
static struct target_path targets[MAX_TARGETS];
static int target_count = 0;
static char paths_buffer[PATHS_BUFFER_LEN] = {0};
static void *hooked_inode_permission = NULL;
static void *hooked_inode_getattr = NULL;

/* 解析路径字符串 */
static void parse_paths(const char *paths_str)
{
    char *buf = paths_buffer;
    char *cursor, *item;
    int i;

    if (!paths_str || !paths_str[0])
        return;

    /* 复制到本地缓冲区 */
    strscpy(buf, paths_str, PATHS_BUFFER_LEN);

    /* 解析逗号分隔的路径 */
    cursor = buf;
    target_count = 0;

    while ((item = strsep(&cursor, ",")) != NULL && target_count < MAX_TARGETS) {
        /* 跳过空格 */
        while (*item == ' ' || *item == '\t')
            item++;

        if (!*item)
            continue;

        /* 复制路径 */
        strscpy(targets[target_count].path, item, TARGET_PATH_LEN);
        targets[target_count].len = strlen(targets[target_count].path);
        target_count++;

        logkd("nohello kpm: target[%d] = %s\n", target_count - 1, item);
    }
}

/* 检查路径是否匹配 */
static int is_target_path(const char *path)
{
    int i;

    if (!path)
        return 0;

    for (i = 0; i < target_count; i++) {
        if (!strcmp(path, targets[i].path)) {
            return 1;
        }
    }

    return 0;
}

/* inode_getattr hook - 隐藏文件 */
static void inode_getattr_before(hook_fargs2_t *fargs, void *udata)
{
    struct path *p = (struct path *)fargs->arg0;
    char buf[TARGET_PATH_LEN];
    char *path_str;

    if (!p || target_count == 0)
        return;

    /* 获取路径字符串 */
    path_str = d_path(p, buf, sizeof(buf));
    if (!path_str || IS_ERR(path_str))
        return;

    /* 检查是否是目标路径 */
    if (is_target_path(path_str)) {
        fargs->skip_origin = 1;
        fargs->ret = (unsigned long)-2; /* -ENOENT */
        logkd("nohello kpm: hiding %s\n", path_str);
    }
}

/* inode_permission hook - 拦截访问 */
static void inode_perm_before(hook_fargs2_t *fargs, void *udata)
{
    struct inode *inode = (struct inode *)fargs->arg0;

    /* 注意：由于无法直接访问 inode->i_ino，这里只是记录日志 */
    /* 实际的隐藏逻辑在 inode_getattr 中实现 */
    logkd("nohello kpm: inode_permission called\n");
}

/* 模块初始化 */
static long nohello_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;
    void *func;

    logkd("nohello kpm: initializing (OnePlus SM8650)\n");
    logkd("nohello kpm: event=%s, args=%s\n", event, args ? args : "null");

    /* 解析参数中的路径 */
    if (args && args[0]) {
        parse_paths(args);
    } else {
        /* 默认路径 */
        parse_paths("/data/local/tmp/nohello");
    }

    if (target_count == 0) {
        logkd("nohello kpm: no targets configured\n");
        return -1;
    }

    logkd("nohello kpm: %d target(s) configured\n", target_count);

    /* Hook security_inode_getattr - 用于隐藏文件 */
    func = (void *)kallsyms_lookup_name("security_inode_getattr");
    if (func) {
        err = hook_wrap2(func, inode_getattr_before, 0, 0);
        if (err) {
            logkd("nohello kpm: hook security_inode_getattr failed: %d\n", err);
        } else {
            hooked_inode_getattr = func;
            logkd("nohello kpm: hooked security_inode_getattr\n");
        }
    } else {
        logkd("nohello kpm: security_inode_getattr not found\n");
    }

    /* Hook security_inode_permission - 用于拦截访问 */
    func = (void *)kallsyms_lookup_name("security_inode_permission");
    if (func) {
        err = hook_wrap2(func, inode_perm_before, 0, 0);
        if (err) {
            logkd("nohello kpm: hook security_inode_permission failed: %d\n", err);
        } else {
            hooked_inode_permission = func;
            logkd("nohello kpm: hooked security_inode_permission\n");
        }
    } else {
        logkd("nohello kpm: security_inode_permission not found\n");
    }

    logkd("nohello kpm: initialized successfully\n");
    return 0;
}

/* 模块退出 */
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

    target_count = 0;
    logkd("nohello kpm: unloaded\n");
    return 0;
}

/* 控制接口 */
static long nohello_control(const char *ctl_args, char *out_msg, int outlen)
{
    char response[256];
    int i, len = 0;

    if (!ctl_args || !ctl_args[0]) {
        /* 显示状态 */
        len += snprintf(response + len, sizeof(response) - len,
                       "nohello kpm: %d target(s)\n", target_count);
        for (i = 0; i < target_count; i++) {
            len += snprintf(response + len, sizeof(response) - len,
                           "  [%d] %s\n", i, targets[i].path);
        }
    } else if (!strcmp(ctl_args, "status")) {
        len += snprintf(response + len, sizeof(response) - len,
                       "nohello kpm: %d target(s), hooks: %s/%s\n",
                       target_count,
                       hooked_inode_permission ? "active" : "inactive",
                       hooked_inode_getattr ? "active" : "inactive");
    } else if (!strcmp(ctl_args, "list")) {
        for (i = 0; i < target_count; i++) {
            len += snprintf(response + len, sizeof(response) - len,
                           "%s%s", i > 0 ? "," : "", targets[i].path);
        }
    } else if (!strncmp(ctl_args, "add=", 4)) {
        /* 添加新路径 */
        if (target_count < MAX_TARGETS) {
            strscpy(targets[target_count].path, ctl_args + 4, TARGET_PATH_LEN);
            targets[target_count].len = strlen(targets[target_count].path);
            target_count++;
            len += snprintf(response + len, sizeof(response) - len,
                           "nohello kpm: added %s\n", ctl_args + 4);
        } else {
            len += snprintf(response + len, sizeof(response) - len,
                           "nohello kpm: max targets reached\n");
        }
    } else {
        len += snprintf(response + len, sizeof(response) - len,
                       "nohello kpm: unknown command '%s'\n", ctl_args);
    }

    if (out_msg && outlen > 0) {
        compat_copy_to_user(out_msg, response, len < outlen ? len : outlen);
    }

    return 0;
}

KPM_INIT(nohello_init);
KPM_EXIT(nohello_exit);
KPM_CTL0(nohello_control);
