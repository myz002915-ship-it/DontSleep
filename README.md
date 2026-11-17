# 禁止休眠 DontSleep

> 使用 [**Craft Anything**](https://github.com/storytold/craft-anything) 逆向还原的 Windows 防休眠小工具，纯 Python + ctypes + tkinter + Pillow 重写，无 MFC、无编译器依赖。

原版 `DontSleep.exe`（MFC 4.2 Unicode，417896 字节）经 Craft Anything v0.6.1 Deep 模式（native 工具集）逆向，确认其核心机制后，用相同的 Win32 API 重写为单文件 Python 程序。

## 功能

- **防待机/睡眠**：`SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)`
- **防屏保**：`SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, FALSE)`
- **防关机/注销**：`SetProcessShutdownParameters` + `WM_QUERYENDSESSION → 0`（否决结束会话）
- **提权**：`SeShutdownPrivilege`（`OpenProcessToken` + `AdjustTokenPrivileges` + `LookupPrivilegeValueW`）
- **唤醒重应用**：`WM_POWERBROADCAST`（`PBT_APMRESUMESUSPEND`）后重新施加阻断
- **定时器**：N 分钟后自动停止阻断
- **单实例**：`CreateMutexW(Global\DontSleep_Rewrite_SingleInstance)`
- **INI 配置持久化**（键名与原版一致：`please_sleep_mode` / `block_standby` / `block_screensaver` / `block_logoff` / `block_shutdown` / `use_hibernate` / `use_timer` / `set_timer` / `activate_if_from_sleep`）
- **系统托盘**：`Shell_NotifyIconW`（左键显示/隐藏，右键菜单）
- **开机自启**：写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`（无需管理员，`pythonw.exe` 启动无控制台黑窗）
- **全中文界面**

## 运行环境

- Windows
- Python 3.x（开发/测试于 3.15）
- 依赖：`Pillow`（生成托盘图标，程序首次运行自动生成 `dontsleep.ico`）

```bash
pip install pillow
```

## 使用

```bash
pythonw dontsleep.py
```

启动后在系统托盘出现图标，设置窗口可勾选各项阻断。

- **开机自启动**：窗口内勾选「开机自启动」即写入注册表（取消勾选即删除）
- **快捷方式**：可手动创建指向 `pythonw.exe` → `dontsleep.py` 的 `.lnk`，图标用 `dontsleep.ico`

## 逆向分析（Craft Anything）

| 项 | 结果 |
|---|---|
| 目标 | `DontSleep.exe`，417896 字节，sha256 `faedcaf0e2ebb267dd7d946e1319a3844f00371ab323462f72b8366aa34ddca9` |
| 类型 | PE，MFC42u（MFC 4.2 Unicode）GUI，系统托盘驻留 |
| 工具 | storytold/craft-anything v0.6.1，Deep 模式，native 工具集 |
| sections | `.text` 137594B @0x401000 / `.rdata` 29628B @0x423000 / `.data` 181956B @0x42b000 / `.rsrc` 141592B @0x458000 |
| 导入 | 495 个（`native-named-addresses-list`） |
| 关键 API | `SetThreadExecutionState` @0x4230f0、`SetSystemPowerState` @0x423178、`SetProcessShutdownParameters` @0x4230e0、`AdjustTokenPrivileges` @0x423020、`LookupPrivilegeValueW` @0x423000、`OpenProcessToken` @0x423024、`SystemParametersInfoW` @0x4236e4、`CreateMutexW`、`CreateThread`、`WritePrivateProfileStringW` |
| 特性串 | `native-strings-find` 命中 56 条：`please_sleep_mode` / `block_screensaver` / `block_logoff` / `block_shutdown` / `block_standby` / `use_hibernate` / `use_timer` / `set_timer` / `activate_if_from_sleep` / `SeShutdownPrivilege` / `IsPwrSuspendAllowed` 等 |

## 文件

```
dontsleep/
├── dontsleep.py   # 主程序（纯 Python + ctypes）
├── dontsleep.ico  # 托盘图标（程序运行时也会自动生成）
├── README.md
├── LICENSE
└── .gitignore
```

## 致谢

- [storytold/craft-anything](https://github.com/storytold/craft-anything) — 逆向研究引擎
- 原版 DontSleep 的功能设计

## 许可

MIT
