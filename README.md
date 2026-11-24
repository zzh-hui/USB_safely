# USB_safely — U盘锁

> U盘锁·电脑防护程序：保护 U 盘里的个人文件，防止别人翻看。
> 设计来源：APPLE_INT 初中时期手写设计方案（v1 草案 + v2.0），由 Geek-Hub 实现。
> 完整设计规格见 [DESIGN.md](DESIGN.md)。

## 当前版本：v2.1.1

**一个安装程序走天下**：`USBsafely-Setup.exe`（安装/卸载二合一，主程序内嵌其中）

### 安装
1. 双击 `USBsafely-Setup.exe`
2. 选择安装目录：**U 盘根目录**（正式使用）或**硬盘目录**（无 U 盘时测试，如 `C:\USBsafely`）
3. 设置启动密码（首次强制 4 位数字）
4. 完成——安装器自动释放主程序、写入密码、注册卸载项

### 使用
- **启动锁定**：双击安装目录里的 `run.bat`（或 `USBsafely.exe`）
- **修改设置**：双击 `setup.bat`（改密码 / 切换解锁模式 / 超级模式）
- **卸载**：控制面板 → 应用 → USB_safely，或再次运行 `USBsafely-Setup.exe`
  （需密码确认，文件+注册表零残留）

### v2.0 新功能

| 功能 | 说明 |
|---|---|
| 解锁模式分级 | 无需解锁 / 普通(数字) / 加密(字母) / 进阶(9位混合) / 密钥模式(≤500位任意字符，支持物理键盘输入 emoji 等任意可见字符) |
| 递进惩罚 | 每累计错 5 次 → 锁定递增 10 分钟；超 60 次 → 格式化兜底（默认关，超级模式开启） |
| 后台待命 | 解锁后缩到系统托盘，双击图标重新锁定；U 盘拔出自动退出 |
| 卸载保护 | 托盘退出需密码；卸载需密码 + 双重确认 |
| 超级模式 | 设置页版本号连点 5 下 → 验证恢复密码 → 重置锁屏密码 / 忘记密码定时重置(24h/30天/365天) / 格式化开关 |
| 安装/卸载二合一 | 单文件安装器，内嵌主程序；卸载零残留 |

### 保留的 v0.1 特性

全屏置顶锁定界面、39 键自带屏幕键盘、快捷键屏蔽（Win/Alt+Tab/Alt+F4 等）、
SHA256 密码存储、取消并弹出 U 盘、首次使用引导。

### 🗺️ v2.1 路线（详见 DESIGN.md）

- 隐藏备份与恢复工具（HMAC 路径 + AES 加密，格式化兜底的数据保险）
- 文件加密保险箱（AES 加密个人文件夹）

## 使用方法

```
U盘
 ├─ USBsafely.exe     主程序（双击=启动锁屏）
 ├─ run.bat           启动锁定
 ├─ Lock.bat          同 run.bat
 ├─ setup.bat         设置模式（改密码）
 ├─ intro.bat         使用说明
 ├─ clean.bat         清除密码文件（慎用）
 ├─ Close.bat         关闭锁屏
 ├─ Stoprun.bat       同 Close.bat
 └─ autorun.inf       (Win7+ 已禁用自动运行，保留作纪念)
```

> ⚠️ Windows 7 起 U 盘自动运行（autorun.inf）已被系统禁用，插入 U 盘后请**双击 run.bat** 或 `USBsafely.exe` 启动锁屏。

1. 把上面的文件复制到 U 盘**根目录**
2. 双击 `setup.bat` → 设置锁屏密码（存入 `password\pw.sf`）
3. 要锁电脑时双击 `run.bat`，输对密码解锁；点「取消并弹出U盘」会安全弹出 U 盘

## 从源码构建

程序为纯 Win32 API C 语言实现（无任何第三方库，符合设计稿"最小方案"）：

```bash
# 主程序
x86_64-w64-mingw32-gcc src/main.c -o USBsafely.exe -municode -mwindows -O2 \
    -luser32 -lgdi32 -lbcrypt -lcfgmgr32 -lshell32 -ladvapi32
# 安装器（内嵌主程序）
cd src && x86_64-w64-mingw32-windres setup.rc -O coff -o setupres.o
x86_64-w64-mingw32-gcc setup.c setupres.o -o USBsafely-Setup.exe -municode -mwindows -O2 \
    -luser32 -lgdi32 -lbcrypt -lshell32 -ladvapi32 -lole32
```

## 制作团队

**APPLE_INT**（设计方案）· Geek-Hub（实现）
