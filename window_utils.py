"""Helpers for positioning Windows console windows during the demos.

These ergonomics helpers keep the client/server consoles side-by-side.  They do
not affect TLS logic but make demonstrations easier to follow.
"""

import os
import sys
import time

def snap_console(side: str = "right", width_ratio: float = 0.5, retries: int = 15, delay: float = 0.05) -> None:
    """Snap the current console window to one side of the screen.

    Args:
      side: ``"left"`` or ``"right"`` target position.
      width_ratio: Portion of the work area to occupy (0.1 .. 1.0).
      retries: How many times to poll for the window handle.
      delay: Delay between retries in seconds.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.  Only affects demo presentation on Windows.
    """
    if sys.platform != "win32":
        return

    import ctypes
    from ctypes import wintypes

    side = side.lower()
    if side not in ("left", "right"):
        side = "right"

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

    GetWindowThreadProcessId = user32.GetWindowThreadProcessId
    GetWindowTextLengthW = user32.GetWindowTextLengthW
    GetWindowTextW = user32.GetWindowTextW
    IsWindowVisible = user32.IsWindowVisible
    EnumWindows = user32.EnumWindows
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def _get_hwnd_by_console_or_pid() -> int:
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            return hwnd

        my_pid = os.getpid()
        found = []

        def _cb(h, _):
            if not IsWindowVisible(h):
                return True
            pid = wintypes.DWORD()
            GetWindowThreadProcessId(h, ctypes.byref(pid))
            if pid.value == my_pid:
                length = GetWindowTextLengthW(h)
                if length > 0:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    GetWindowTextW(h, buf, length + 1)
                    if buf.value.strip():
                        found.append(h)
            return True

        EnumWindows(EnumWindowsProc(_cb), 0)
        return found[0] if found else 0

    hwnd = 0
    for _ in range(retries):
        hwnd = _get_hwnd_by_console_or_pid()
        if hwnd:
            break
        time.sleep(delay)
    if not hwnd:
        return

    MONITOR_DEFAULTTONEAREST = 2

    class RECT(ctypes.Structure):
        _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                    ("right", wintypes.LONG), ("bottom", wintypes.LONG)]

    class MONITORINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD),
                    ("rcMonitor", RECT),
                    ("rcWork", RECT),
                    ("dwFlags", wintypes.DWORD)]

    hmon = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
    mi = MONITORINFO()
    mi.cbSize = ctypes.sizeof(MONITORINFO)
    if not user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
        return

    work = mi.rcWork
    work_w = max(1, work.right - work.left)
    work_h = max(1, work.bottom - work.top)

    width_ratio = max(0.1, min(1.0, float(width_ratio)))
    new_w = int(work_w * width_ratio)
    new_h = work_h

    if side == "left":
        new_x = work.left
    else:  # "right"
        new_x = work.left + (work_w - new_w)

    new_y = work.top

    SWP_NOZORDER = 0x0004
    SWP_SHOWWINDOW = 0x0040
    user32.SetWindowPos(hwnd, 0, new_x, new_y, new_w, new_h, SWP_NOZORDER | SWP_SHOWWINDOW)
