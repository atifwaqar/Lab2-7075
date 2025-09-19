# -*- coding: utf-8 -*-
"""
Reusable WhatsApp-style TUI for terminal chat apps using prompt_toolkit.

Exports:
  - create_chat_app(title_text: str, send_callback: Callable[[str], None]) -> Application
    Returns a prompt_toolkit Application with:
      - app.append_peer(msg: str)
      - app.append_system(msg: str)
    Call app.run() to start the UI.
"""

import threading
import textwrap
import shutil

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, VSplit, Layout, Window
from prompt_toolkit.widgets import TextArea, Label
from prompt_toolkit.styles import Style


# -------------------- layout helpers --------------------
def _term_width() -> int:
    try:
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        cols = 80
    return max(40, min(120, cols))  # clamp for nicer bubbles on ultrawide


def _wrap_lines(text: str, max_content: int):
    return textwrap.wrap(
        text.replace("\t", "    "),
        width=max_content,
        break_long_words=True,
        replace_whitespace=False,
        drop_whitespace=False,
    ) or [""]


def _align_line(line: str, side: str, margin: int = 2) -> str:
    w = _term_width()
    if side == "right":
        pad = max(0, w - len(line) - margin)
        return " " * pad + line
    else:
        return " " * margin + line


def make_bubble(text: str, side: str = "left") -> str:
    """
    Build a message bubble using the same rounded box-drawing characters
    for BOTH sides; only alignment differs (left for peer, right for me).
    """
    w = _term_width()
    max_content = max(16, min(60, w - 12))  # bubble content width cap
    lines = _wrap_lines(text, max_content)
    inner = max(len(l) for l in lines) if lines else 0
    pad = 1  # inner horizontal padding

    tl, tr, bl, br, h, v = "╭", "╮", "╰", "╯", "─", "│"

    top    = tl + h * (inner + 2 * pad) + tr
    bottom = bl + h * (inner + 2 * pad) + br
    middle = [f"{v}{' ' * pad}{l.ljust(inner)}{' ' * pad}{v}" for l in lines or [""]]

    bubble_lines = [top] + middle + [bottom]

    side_align = "right" if side == "right" else "left"
    aligned = [_align_line(line, side_align) for line in bubble_lines]
    return "\n".join(aligned)


def _append_line(area: TextArea, text: str):
    """Append text to end of log and keep viewport at bottom."""
    buf = area.buffer
    buf.cursor_position = len(buf.text)
    if text and not text.endswith("\n"):
        text = text + "\n"
    buf.insert_text(text)
    try:
        w = area.window
        w.vertical_scroll = max(0, len(buf.text.splitlines()) - 1)
    except Exception:
        pass


# -------------------- public factory --------------------
def create_chat_app(title_text: str, send_callback):
    """
    Create a full-screen prompt_toolkit chat UI.

    send_callback(msg: str) is invoked when the user hits Enter.
    The returned app has:
      - app.append_peer(msg)
      - app.append_system(msg)
    """
    log = TextArea(
        text="",
        scrollbar=True,
        wrap_lines=False,
        read_only=False,   # programmatic inserts
        focusable=False,
        style="class:log",
    )

    kb = KeyBindings()

    @kb.add("c-c")
    @kb.add("c-q")
    def _(event):
        event.app.exit()

    def on_accept(_buffer):
        msg = input_field.text
        if msg.strip():
            _append_line(log, make_bubble(msg, side="right"))
            _append_line(log, "")
            send_callback(msg)
        input_field.buffer.reset()

    prompt_lbl = Label(text="You: ", style="class:label")
    input_field = TextArea(
        height=1,
        prompt="",
        multiline=False,
        wrap_lines=False,
        style="class:input",
        accept_handler=on_accept,
    )

    root = HSplit(
        [
            Label(text=title_text, style="class:title"),
            Window(height=1, char="-", style="class:rule"),
            log,
            Window(height=1, char="-", style="class:rule"),
            VSplit([prompt_lbl, input_field], padding=0),
        ]
    )

    style = Style.from_dict(
        {
            "title": "bold ansicyan",
            "rule": "ansiyellow",
            "log": "bg:#101010 #e5e5e5",
            "label": "ansigreen",
            "input": "bg:#202020 #ffffff",
        }
    )

    app = Application(
        layout=Layout(root, focused_element=input_field),
        key_bindings=kb,
        style=style,
        full_screen=True,
    )

    # Thread-safe appenders for background recv threads:
    _lock = threading.Lock()

    def _run_on_ui_thread(fn):
        """Ensure prompt_toolkit buffer mutations happen on the UI thread."""

        if app.is_running:
            try:
                app.call_from_executor(fn)
                return
            except Exception:
                pass
        # Fallback for early log messages before the app starts running or if
        # call_from_executor is unavailable.  In those cases we're already on
        # the main thread and can safely execute immediately.
        fn()

    def _append_peer(m: str):
        def _do_append():
            with _lock:
                _append_line(log, make_bubble(m, side="left"))
                _append_line(log, "")
            try:
                app.invalidate()
            except Exception:
                pass

        _run_on_ui_thread(_do_append)

    def _append_sys(m: str):
        def _do_append():
            with _lock:
                _append_line(log, m)
            try:
                app.invalidate()
            except Exception:
                pass

        _run_on_ui_thread(_do_append)

    app.append_peer = _append_peer     # type: ignore[attr-defined]
    app.append_system = _append_sys    # type: ignore[attr-defined]
    return app
