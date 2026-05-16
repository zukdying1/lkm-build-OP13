# OnePlus SM8650 (Ace 3 Pro) 适配指南

## 设备信息
- **设备**: OnePlus Ace 3 Pro
- **处理器**: SM8650 (骁龙 8 Gen 3)
- **内核**: 6.1.x (Android 14)
- **KMI**: android14-6.1

## 前置要求

### 1. 解锁 Bootloader
OnePlus 设备需要解锁 bootloader 才能加载内核模块：
```bash
# 进入 fastboot 模式
adb reboot bootloader

# 解锁（会清除数据）
fastboot flashing unlock
```

### 2. 安装 KernelPatch
KPM 需要 KernelPatch 才能运行：
```bash
# 从 https://github.com/bmax121/KernelPatch/releases 下载
# 按照 KernelPatch 文档安装
```

### 3. 检查内核配置
```bash
adb shell su -c "zcat /proc/config.gz | grep -E 'KALLSYMS|MODULES'"
```

确保以下配置启用：
- `CONFIG_KALLSYMS=y`
- `CONFIG_MODULES=y`
- `CONFIG_MODULE_UNLOAD=y`

## 使用方法

### 方法1：使用预编译的 KPM

1. 从 GitHub Actions 下载 `android14-6.1_nohello.kpm`
2. 推送到设备：
```bash
adb push android14-6.1_nohello.kpm /data/local/tmp/nohello.kpm
```

3. 加载 KPM（使用 KernelPatch 的命令）：
```bash
# 通过 KernelPatch 加载
sc_kpm_load <key> /data/local/tmp/nohello.kpm "/data/local/tmp/nohello"
```

### 方法2：自定义目标路径

修改加载参数，支持多路径（逗号分隔）：
```bash
# 单个路径
sc_kpm_load <key> /data/local/tmp/nohello.kpm "/data/local/tmp/secret_file"

# 多个路径
sc_kpm_load <key> /data/local/tmp/nohello.kpm "/data/local/tmp/file1,/data/local/tmp/file2,/system/app/TargetApp"
```

### 方法3：运行时管理

使用控制接口管理：
```bash
# 查看状态
sc_kpm_control <key> "kpm-nohello" "status" <out_buf> <out_len>

# 列出所有目标
sc_kpm_control <key> "kpm-nohello" "list" <out_buf> <out_len>

# 添加新路径
sc_kpm_control <key> "kpm-nohello" "add=/data/local/tmp/new_file" <out_buf> <out_len>
```

## OnePlus 特殊注意事项

### 1. dm-verity
OnePlus 设备默认启用 dm-verity，可能需要禁用：
```bash
# 在 fastboot 模式下
fastboot disable-verity
```

### 2. 模块签名
OnePlus 内核可能需要禁用模块签名：
```bash
adb shell su -c "echo 0 > /proc/sys/kernel/module_signature_enforce"
```

### 3. SELinux
SELinux 可能阻止模块加载，需要设置为 permissive：
```bash
adb shell su -c "setenforce 0"
```

## 测试步骤

1. 创建测试文件：
```bash
adb shell "echo 'secret data' > /data/local/tmp/nohello"
adb shell "cat /data/local/tmp/nohello"
```

2. 加载 KPM：
```bash
sc_kpm_load <key> /data/local/tmp/nohello.kpm "/data/local/tmp/nohello"
```

3. 验证隐藏：
```bash
adb shell "ls -la /data/local/tmp/nohello"
# 应该返回 "No such file or directory"

adb shell "cat /data/local/tmp/nohello"
# 应该返回 "No such file or directory"
```

4. 卸载 KPM：
```bash
sc_kpm_unload <key> "kpm-nohello"
```

## 故障排除

### 问题1：符号未找到
```
nohello kpm: security_inode_getattr not found
```
**解决方案**：检查内核是否有 CONFIG_SECURITY 启用

### 问题2：权限被拒绝
```
Permission denied
```
**解决方案**：确保 SELinux 为 permissive 或添加适当的 sepolicy

### 问题3：内核版本不匹配
```
insmod: ERROR: could not insert module
```
**解决方案**：确保使用正确 KMI 版本的模块

## 内核源码编译（可选）

如果需要更深度的适配，可以编译自定义内核：

```bash
# 克隆 OnePlus 内核源码
git clone https://github.com/OnePlusOSS/android_kernel_oneplus_sm8650.git
cd android_kernel_oneplus_sm8650
git checkout oneplus/sm8650_b_16.0.0_ace_3_pro

# 配置交叉编译工具链
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64

# 编译内核模块
make vendor/cardiace_defconfig
make modules
```

## 参考链接

- [KernelPatch 官方文档](https://github.com/bmax121/KernelPatch)
- [OnePlus 内核源码](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8650)
- [KernelSU 安装指南](https://kernelsu.org/)

## 支持

如有问题，请提供以下信息：
1. 设备型号和系统版本
2. 内核版本（`uname -r`）
3. 内核配置（`/proc/config.gz`）
4. 错误日志（`dmesg | grep nohello`）
