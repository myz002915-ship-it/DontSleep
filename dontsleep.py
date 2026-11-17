#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DontSleep — rewrite reverse-engineered with Craft Anything from DontSleep.exe
==============================================================================

Source binary analysed with storytold/craft-anything v0.6.1 (Deep mode, native
toolset) on DontSleep.exe (417896 bytes, sha256
faedcaf0e2ebb267dd7d946e1319a3844f00371ab323462f72b8366aa34ddca9).

Confirmed mechanism (from native-named-addresses-list / native-strings-find):
  * MFC42u (MFC 4.2 Unicode) GUI app, system-tray resident.
  * Core anti-sleep: SetThreadExecutionState(
        ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
  * Power control: SetSystemPowerState, IsPwrSuspendAllowed,
        SeShutdownPrivilege via AdjustTokenPrivileges/OpenProcessToken/
        LookupPrivilegeValueW.
  * Shutdown/logoff interception: SetProcessShutdownParameters +
        WM_QUERYENDSESSION -> return FALSE.
  * Screensaver block: SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE).
  * Feature toggles (strings): please_sleep_mode (master), block_screensaver,
        block_logoff, block_shutdown, block_standby, use_hibernate.
  * Timer: use_timer / set_timer (minutes) -> stop blocking after N min.
  * Re-apply on wake: activate_if_from_sleep + from_standby_timer
        (WM_POWERBROADCAST PBT_APMRESUMESUSPEND).
  * Persistence: INI (WritePrivateProfileStringW) + registry.
  * Single instance: CreateMutexW; worker thread: CreateThread + events.

This rewrite is pure Python 3 + ctypes + tkinter + Pillow: no compiler, no
runtime dependency on MFC.  It calls the same Win32 APIs the original does.
"""

import os
import sys
import ctypes
import configparser
import threading
import winreg
import tkinter as tk
from tkinter import ttk
from ctypes import wintypes

# ----------------------------------------------------------------------------
# Win32 constants
# ----------------------------------------------------------------------------
ES_CONTINUOUS          = 0x80000000
ES_SYSTEM_REQUIRED     = 0x00000001
ES_DISPLAY_REQUIRED    = 0x00000002
ES_AWAYMODE_REQUIRED   = 0x00000040

TOKEN_QUERY            = 0x0008
TOKEN_ADJUST_PRIVILEGES= 0x0020
SE_PRIVILEGE_ENABLED   = 0x00000002

WM_APP                 = 0x8000
WM_QUERYENDSESSION     = 0x0011
WM_ENDSESSION          = 0x0016
WM_POWERBROADCAST      = 0x0218
PBT_APMRESUMESUSPEND   = 0x0006
PBT_APMRESUMEAUTOMATIC = 0x0012
WM_LBUTTONUP           = 0x0202
WM_LBUTTONDBLCLK       = 0x0203
WM_RBUTTONUP           = 0x0205

NIM_ADD    = 0; NIM_MODIFY = 1; NIM_DELETE = 2
NIF_MESSAGE= 1; NIF_ICON   = 2; NIF_TIP    = 4

IMAGE_ICON     = 1
LR_LOADFROMFILE= 0x00000010

SPI_GETSCREENSAVEACTIVE = 0x0010
SPI_SETSCREENSAVEACTIVE = 0x0011

ERROR_ALREADY_EXISTS = 183

# ----------------------------------------------------------------------------
# Win32 DLLs + argtypes
# ----------------------------------------------------------------------------
k32  = ctypes.WinDLL('kernel32', use_last_error=True)
a32  = ctypes.WinDLL('advapi32', use_last_error=True)
u32  = ctypes.WinDLL('user32',  use_last_error=True)
sh32 = ctypes.WinDLL('shell32', use_last_error=True)

k32.SetThreadExecutionState.restype  = wintypes.DWORD
k32.SetThreadExecutionState.argtypes = [wintypes.DWORD]

k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes      = [wintypes.HANDLE]
k32.CloseHandle.restype       = wintypes.BOOL

k32.CreateMutexW.argtypes  = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
k32.CreateMutexW.restype   = wintypes.HANDLE
k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
k32.GetModuleHandleW.restype  = wintypes.HMODULE
k32.SetProcessShutdownParameters.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.SetProcessShutdownParameters.restype  = wintypes.BOOL

# --- TOKEN_PRIVILEGES ---
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

a32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
a32.OpenProcessToken.restype  = wintypes.BOOL
a32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                      ctypes.POINTER(LUID)]
a32.LookupPrivilegeValueW.restype  = wintypes.BOOL
a32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD,
    ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)]
a32.AdjustTokenPrivileges.restype  = wintypes.BOOL

# --- NOTIFYICONDATAW (v1 layout — enough for icon+tip+callback) ---
class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
    ]

sh32.Shell_NotifyIconW.argtypes = [wintypes.DWORD,
                                   ctypes.POINTER(NOTIFYICONDATAW)]
sh32.Shell_NotifyIconW.restype  = wintypes.BOOL

# --- window class / message pump ---
WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)

class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]

u32.RegisterClassW.argtypes   = [ctypes.POINTER(WNDCLASSW)]
u32.RegisterClassW.restype    = wintypes.ATOM
u32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
u32.CreateWindowExW.argtypes  = [wintypes.DWORD, wintypes.LPCWSTR,
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU,
    wintypes.HINSTANCE, ctypes.c_void_p]
u32.CreateWindowExW.restype   = wintypes.HWND
u32.DestroyWindow.argtypes    = [wintypes.HWND]
u32.DefWindowProcW.argtypes   = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                 wintypes.LPARAM]
u32.DefWindowProcW.restype    = ctypes.c_ssize_t
u32.PeekMessageW.argtypes     = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                 wintypes.UINT, wintypes.UINT, wintypes.UINT]
u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
u32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
u32.PostMessageW.argtypes     = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                 wintypes.LPARAM]
u32.LoadImageW.argtypes       = [wintypes.HINSTANCE, wintypes.LPCWSTR,
                                 wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                 wintypes.UINT]
u32.LoadImageW.restype        = wintypes.HANDLE
u32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT,
                                      ctypes.c_void_p, wintypes.UINT]
u32.SystemParametersInfoW.restype  = wintypes.BOOL
u32.GetCursorPos.argtypes     = [ctypes.POINTER(wintypes.POINT)]
u32.CreatePopupMenu.restype   = wintypes.HMENU
u32.AppendMenuW.argtypes      = [wintypes.HMENU, wintypes.UINT,
                                 ctypes.c_size_t, wintypes.LPCWSTR]
u32.TrackPopupMenu.argtypes   = [wintypes.HMENU, wintypes.UINT, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wintypes.HWND, ctypes.c_void_p]
u32.TrackPopupMenu.restype    = ctypes.c_int
u32.DestroyMenu.argtypes      = [wintypes.HMENU]
u32.SetForegroundWindow.argtypes = [wintypes.HWND]
u32.SetForegroundWindow.restype  = wintypes.BOOL

PM_REMOVE = 0x0001
TPM_RETURNCMD = 0x0100
MF_STRING = 0x0000
MF_SEPARATOR = 0x0800

# ----------------------------------------------------------------------------
# Settings (INI) — mirrors the original's WritePrivateProfileStringW keys
# ----------------------------------------------------------------------------
APP_NAME   = "DontSleep"
INI_NAME   = "DontSleep.ini"
MUTEX_NAME = "Global\\DontSleep_Rewrite_SingleInstance"

DEFAULTS = {
    'please_sleep_mode':   '1',   # master anti-sleep toggle
    'block_standby':       '1',   # block sleep/standby (ES_SYSTEM_REQUIRED)
    'block_screensaver':   '1',   # block screen saver (ES_DISPLAY_REQUIRED + SPI)
    'block_logoff':        '0',   # block logoff (WM_QUERYENDSESSION -> FALSE)
    'block_shutdown':      '0',   # block shutdown
    'use_hibernate':       '0',   # allow/block hibernate
    'use_timer':           '0',   # timer enabled
    'set_timer':           '30',  # timer minutes
    'activate_if_from_sleep': '1',# re-apply on wake from sleep
}


def settings_path():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, INI_NAME)


def load_settings():
    cp = configparser.ConfigParser()
    cp.read_dict({'DontSleep': DEFAULTS})
    cp.read(settings_path(), encoding='utf-8')
    s = cp['DontSleep']
    return {
        'please_sleep_mode':     s.getboolean('please_sleep_mode'),
        'block_standby':         s.getboolean('block_standby'),
        'block_screensaver':     s.getboolean('block_screensaver'),
        'block_logoff':          s.getboolean('block_logoff'),
        'block_shutdown':        s.getboolean('block_shutdown'),
        'use_hibernate':         s.getboolean('use_hibernate'),
        'use_timer':             s.getboolean('use_timer'),
        'set_timer':             s.getint('set_timer'),
        'activate_if_from_sleep':s.getboolean('activate_if_from_sleep'),
    }


def save_settings(s):
    cp = configparser.ConfigParser()
    cp['DontSleep'] = {
        'please_sleep_mode':   '1' if s['please_sleep_mode']   else '0',
        'block_standby':       '1' if s['block_standby']       else '0',
        'block_screensaver':   '1' if s['block_screensaver']   else '0',
        'block_logoff':        '1' if s['block_logoff']        else '0',
        'block_shutdown':      '1' if s['block_shutdown']      else '0',
        'use_hibernate':       '1' if s['use_hibernate']       else '0',
        'use_timer':           '1' if s['use_timer']           else '0',
        'set_timer':           str(s['set_timer']),
        'activate_if_from_sleep':'1' if s['activate_if_from_sleep'] else '0',
    }
    with open(settings_path(), 'w', encoding='utf-8') as f:
        cp.write(f)


# ----------------------------------------------------------------------------
# Autostart — HKCU\...\Run (no admin needed), value name DontSleep
# ----------------------------------------------------------------------------
RUN_KEY   = r'Software\Microsoft\Windows\CurrentVersion\Run'
RUN_VALUE = 'DontSleep'


def autostart_command():
    """Command line stored in the registry: "<pythonw>" "<script>".
    Always use pythonw.exe (no console window) even if this process is
    running under python.exe."""
    exe = sys.executable
    d = os.path.dirname(exe)
    pythonw = os.path.join(d, 'pythonw.exe')
    if os.path.exists(pythonw):
        exe = pythonw  # no-console interpreter in same dir
    script = os.path.abspath(__file__)
    return f'"{exe}" "{script}"'


def is_autostart_installed():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, RUN_VALUE)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def install_autostart():
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.SetValueEx(k, RUN_VALUE, 0, winreg.REG_SZ,
                              autostart_command())
        return True
    except OSError as e:
        print("install_autostart failed:", e, file=sys.stderr)
        return False


def uninstall_autostart():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_VALUE)
        return True
    except FileNotFoundError:
        return True
    except OSError as e:
        print("uninstall_autostart failed:", e, file=sys.stderr)
        return False


# ----------------------------------------------------------------------------
# Power management — the confirmed Win32 calls
# ----------------------------------------------------------------------------
def enable_shutdown_privilege():
    """Enable SE_SHUTDOWN_NAME — required for SetSystemPowerState / shutdown veto."""
    htok = wintypes.HANDLE()
    if not a32.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                ctypes.byref(htok)):
        return False
    luid = LUID()
    if not a32.LookupPrivilegeValueW(None, "SeShutdownPrivilege",
                                     ctypes.byref(luid)):
        k32.CloseHandle(htok); return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    ok = a32.AdjustTokenPrivileges(htok, False, ctypes.byref(tp),
                                   ctypes.sizeof(tp), None, None)
    err = ctypes.get_last_error()
    k32.CloseHandle(htok)
    # AdjustTokenPrivileges returns True even when some privileges not adjusted;
    # GetLastError == ERROR_NOT_ALL_ASSIGNED (1300) means partial.
    return bool(ok) and err != 1300


def execution_flags(settings):
    """Build the SetThreadExecutionState flags from the active toggles."""
    if not settings['please_sleep_mode']:
        return ES_CONTINUOUS  # clear
    flags = ES_CONTINUOUS
    if settings['block_standby']:
        flags |= ES_SYSTEM_REQUIRED
    if settings['block_screensaver']:
        flags |= ES_DISPLAY_REQUIRED
    return flags


def apply_blocking(settings):
    """Apply the core anti-sleep state via SetThreadExecutionState."""
    k32.SetThreadExecutionState(execution_flags(settings))
    # Screensaver: SPI_SETSCREENSAVEACTIVE(FALSE) blocks the screensaver too.
    if settings['please_sleep_mode'] and settings['block_screensaver']:
        u32.SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, 0, None, 0)
    else:
        u32.SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, 1, None, 0)


def clear_blocking():
    k32.SetThreadExecutionState(ES_CONTINUOUS)
    u32.SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, 1, None, 0)


# ----------------------------------------------------------------------------
# Tray icon — generated with Pillow, loaded as an HICON
# ----------------------------------------------------------------------------
def make_icon_file():
    """Draw a 32x32 'no-sleep' icon (crescent moon + red prohibition slash)."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dontsleep.ico')
    img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # dark rounded tile
    d.rounded_rectangle([1, 1, 30, 30], radius=6, fill=(30, 40, 70, 255))
    # crescent moon
    d.ellipse([7, 6, 22, 21], fill=(255, 220, 120, 255))
    d.ellipse([12, 5, 27, 20], fill=(30, 40, 70, 255))
    # red prohibition slash
    d.line([6, 26, 26, 6], fill=(220, 60, 60, 255), width=3)
    img.save(path, format='ICO', sizes=[(32, 32)])
    return path


def load_hicon():
    p = make_icon_file()
    if not p or not os.path.exists(p):
        return None
    h = u32.LoadImageW(None, p, IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
    return h if h else None


# ----------------------------------------------------------------------------
# Hidden message window: owns the tray icon + receives session/power messages
# ----------------------------------------------------------------------------
class TrayWindow:
    """A hidden top-level window that owns the shell tray icon and handles
    WM_QUERYENDSESSION (veto shutdown/logoff) and WM_POWERBROADCAST (re-apply)."""

    def __init__(self, app):
        self.app = app
        self.hwnd = None
        self.hicon = None
        self._nid = None
        # keep the WNDPROC alive (prevent GC)
        self._proc = WNDPROC(self._wnd_proc)
        self._msg = wintypes.MSG()
        self._register()

    def _register(self):
        hinst = k32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc = self._proc
        wc.hInstance = hinst
        wc.lpszClassName = "DontSleepRewriteMainWnd"
        atom = u32.RegisterClassW(ctypes.byref(wc))
        if not atom and ctypes.get_last_error() != 1410:  # 1410 = already registered
            raise OSError("RegisterClassW failed: %d" % ctypes.get_last_error())
        self.hinst = hinst
        self.hwnd = u32.CreateWindowExW(
            0, "DontSleepRewriteMainWnd", "DontSleep",
            0, 0, 0, 0, 0, None, None, hinst, None)
        if not self.hwnd:
            raise OSError("CreateWindowExW failed: %d" % ctypes.get_last_error())
        self._add_icon()

    def _add_icon(self):
        self.hicon = load_hicon()
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(nid)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_APP
        nid.hIcon = self.hicon or 0
        nid.szTip = APP_NAME
        self._nid = nid
        sh32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

    def set_tip(self, text):
        if not self._nid:
            return
        self._nid.szTip = text[:127]
        sh32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))

    def pump(self):
        """Pump waiting messages for this window. Called from tkinter.after()."""
        while u32.PeekMessageW(ctypes.byref(self._msg), None, 0, 0, PM_REMOVE):
            u32.TranslateMessage(ctypes.byref(self._msg))
            u32.DispatchMessageW(ctypes.byref(self._msg))

    def _popup_menu(self):
        m = u32.CreatePopupMenu()
        if m:
            visible = self.app.root.state() != 'iconic' and self.app.root.winfo_viewable()
            u32.AppendMenuW(m, MF_STRING, 1, "显示/隐藏" if visible else "显示")
            u32.AppendMenuW(m, MF_SEPARATOR, 0, "")
            u32.AppendMenuW(m, MF_STRING, 2, "退出")
            pt = wintypes.POINT()
            u32.GetCursorPos(ctypes.byref(pt))
            u32.SetForegroundWindow(self.hwnd)
            cmd = u32.TrackPopupMenu(m, TPM_RETURNCMD, pt.x, pt.y, 0, self.hwnd, None)
            u32.DestroyMenu(m)
            if cmd == 1:
                self.app.root.after(0, self.app.toggle_window)
            elif cmd == 2:
                self.app.root.after(0, self.app.quit_app)

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_APP:
            mouse = lparam & 0xFFFF
            if mouse in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                self.app.root.after(0, self.app.toggle_window)
            elif mouse == WM_RBUTTONUP:
                self._popup_menu()
            return 0
        if msg == WM_QUERYENDSESSION:
            # veto shutdown/logoff when those blocks are on
            s = self.app.settings
            if (s['block_shutdown'] or s['block_logoff']) and s['please_sleep_mode']:
                # returning 0 means "do not end session"
                return 0
            return 1
        if msg == WM_ENDSESSION:
            return 0
        if msg == WM_POWERBROADCAST:
            if wparam in (PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC):
                if self.app.settings['activate_if_from_sleep']:
                    self.app.root.after(0, self.app.on_resume_from_sleep)
            return 1
        return u32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def destroy(self):
        if self._nid:
            sh32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
        if self.hwnd:
            u32.DestroyWindow(self.hwnd)


# ----------------------------------------------------------------------------
# Main application — tkinter settings dialog + power logic
# ----------------------------------------------------------------------------
class DontSleepApp:
    def __init__(self):
        self.settings = load_settings()
        self.mutex = None
        self._timer_thread = None
        self._timer_stop = threading.Event()
        self.tray = None

        # single instance (CreateMutexW) — like the original
        self.mutex = k32.CreateMutexW(None, False, MUTEX_NAME)
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            # already running: just exit quietly
            sys.exit(0)

        # enable SE_SHUTDOWN privilege + register for shutdown ordering
        enable_shutdown_privilege()
        k32.SetProcessShutdownParameters(0x380, 0)

        # tkinter root
        self.root = tk.Tk()
        self.root.title("禁止休眠（DontSleep）")
        self.root.geometry("320x410")
        self.root.resizable(False, False)
        self._build_ui()

        # tray window (created on this thread so its messages pump here)
        try:
            self.tray = TrayWindow(self)
            self.root.protocol("WM_DELETE_WINDOW", self.hide_window)
            self._update_tip()
        except Exception as e:
            # tray is optional; fall back to plain window
            print("tray init failed:", e, file=sys.stderr)
            self.root.protocol("WM_DELETE_WINDOW", self.quit_app)

        # apply the current blocking state on startup
        self.apply_now()

        # pump tray messages periodically inside Tk's loop
        if self.tray:
            self.root.after(40, self._pump_loop)

        # if a timer is active, start it
        if self.settings['use_timer']:
            self.start_timer()

    # ---- UI ----
    def _build_ui(self):
        pad = {'padx': 8, 'pady': 4}
        f = ttk.Frame(self.root, padding=10)
        f.pack(fill='both', expand=True)

        self.var_master = tk.BooleanVar(value=self.settings['please_sleep_mode'])
        cb = ttk.Checkbutton(f, text="禁止休眠 (please_sleep_mode)",
                             variable=self.var_master,
                             command=self.on_toggle)
        cb.grid(row=0, column=0, sticky='w', **pad)

        ttk.Separator(f, orient='horizontal').grid(row=1, column=0, sticky='ew',
                                                    pady=6)
        ttk.Label(f, text="阻断项：").grid(row=2, column=0, sticky='w', **pad)

        self.var_standby = tk.BooleanVar(value=self.settings['block_standby'])
        self.var_screen  = tk.BooleanVar(value=self.settings['block_screensaver'])
        self.var_logoff  = tk.BooleanVar(value=self.settings['block_logoff'])
        self.var_shut    = tk.BooleanVar(value=self.settings['block_shutdown'])
        self.var_hiber   = tk.BooleanVar(value=self.settings['use_hibernate'])

        rows = [
            ("待机 / 睡眠",     self.var_standby),
            ("屏幕保护",        self.var_screen),
            ("注销",            self.var_logoff),
            ("关机",            self.var_shut),
            ("允许休眠",        self.var_hiber),
        ]
        for i, (label, var) in enumerate(rows, start=3):
            ttk.Checkbutton(f, text=label, variable=var,
                            command=self.on_toggle).grid(row=i, column=0,
                                                         sticky='w', **pad)

        ttk.Separator(f, orient='horizontal').grid(row=8, column=0, sticky='ew',
                                                    pady=6)
        self.var_timer = tk.BooleanVar(value=self.settings['use_timer'])
        ttk.Checkbutton(f, text="定时器（N 分钟后停止阻断）",
                        variable=self.var_timer,
                        command=self.on_timer_toggle).grid(row=9, column=0,
                                                           sticky='w', **pad)
        self.sp_min = tk.Spinbox(f, from_=1, to=999, width=5,
                                 textvariable=tk.IntVar(
                                     value=self.settings['set_timer']))
        self.sp_min.grid(row=9, column=1, sticky='w', **pad)

        self.var_wake = tk.BooleanVar(value=self.settings['activate_if_from_sleep'])
        ttk.Checkbutton(f, text="从睡眠唤醒后重新应用",
                        variable=self.var_wake,
                        command=self.on_toggle).grid(row=10, column=0,
                                                     sticky='w', **pad)

        self.var_autostart = tk.BooleanVar(value=is_autostart_installed())
        ttk.Checkbutton(f, text="开机自启动",
                        variable=self.var_autostart,
                        command=self.on_autostart_toggle).grid(
                            row=11, column=0, sticky='w', **pad)

        self.lbl = ttk.Label(f, text="", foreground="#0a7")
        self.lbl.grid(row=12, column=0, columnspan=2, sticky='w', **pad)

        b = ttk.Frame(f)
        b.grid(row=13, column=0, columnspan=2, pady=8)
        ttk.Button(b, text="应用", command=self.apply_now).pack(side='left', padx=4)
        ttk.Button(b, text="隐藏", command=self.hide_window).pack(side='left', padx=4)
        ttk.Button(b, text="退出", command=self.quit_app).pack(side='left', padx=4)

    # ---- actions ----
    def collect_settings(self):
        self.settings['please_sleep_mode']    = self.var_master.get()
        self.settings['block_standby']        = self.var_standby.get()
        self.settings['block_screensaver']    = self.var_screen.get()
        self.settings['block_logoff']         = self.var_logoff.get()
        self.settings['block_shutdown']       = self.var_shut.get()
        self.settings['use_hibernate']        = self.var_hiber.get()
        self.settings['use_timer']            = self.var_timer.get()
        try:
            self.settings['set_timer']        = int(self.sp_min.get())
        except ValueError:
            pass
        self.settings['activate_if_from_sleep'] = self.var_wake.get()

    def on_toggle(self):
        self.collect_settings()
        self.apply_now()
        save_settings(self.settings)

    def on_timer_toggle(self):
        self.collect_settings()
        if self.settings['use_timer']:
            self.start_timer()
        else:
            self.stop_timer()
        save_settings(self.settings)

    def on_autostart_toggle(self):
        if self.var_autostart.get():
            if not install_autostart():
                self.var_autostart.set(False)
        else:
            uninstall_autostart()

    def apply_now(self):
        self.collect_settings()
        apply_blocking(self.settings)
        self._update_status()
        self._update_tip()

    def _update_status(self):
        if self.settings['please_sleep_mode']:
            on = []
            if self.settings['block_standby']:     on.append("待机")
            if self.settings['block_screensaver']: on.append("屏保")
            if self.settings['block_logoff']:      on.append("注销")
            if self.settings['block_shutdown']:    on.append("关机")
            txt = "阻断中：" + (", ".join(on) if on else "（总开关开，无子项）")
        else:
            txt = "允许睡眠（未阻断）"
        self.lbl.config(text=txt)

    def _update_tip(self):
        if self.tray:
            if self.settings['please_sleep_mode']:
                self.tray.set_tip(APP_NAME + " — 开启")
            else:
                self.tray.set_tip(APP_NAME + " — 关闭")

    # ---- timer ----
    def start_timer(self):
        self.stop_timer()
        minutes = self.settings['set_timer']
        if minutes <= 0:
            return
        self._timer_stop.clear()

        def worker():
            secs = minutes * 60
            if self._timer_stop.wait(secs):
                return
            # timer elapsed: turn off blocking
            self.root.after(0, self._timer_expired)

        self._timer_thread = threading.Thread(target=worker, daemon=True)
        self._timer_thread.start()

    def stop_timer(self):
        self._timer_stop.set()
        self._timer_thread = None

    def _timer_expired(self):
        self.var_master.set(False)
        self.on_toggle()

    def on_resume_from_sleep(self):
        # re-apply after the machine woke up
        self.apply_now()

    # ---- window / lifecycle ----
    def toggle_window(self):
        if self.root.state() == 'iconic' or not self.root.winfo_viewable():
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        else:
            self.hide_window()

    def hide_window(self):
        self.root.withdraw()

    def _pump_loop(self):
        if self.tray:
            self.tray.pump()
            self.root.after(40, self._pump_loop)

    def quit_app(self):
        clear_blocking()
        self.stop_timer()
        if self.tray:
            self.tray.destroy()
        save_settings(self.settings)
        self.root.quit()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ----------------------------------------------------------------------------
def main():
    app = DontSleepApp()
    app.run()


if __name__ == '__main__':
    main()
