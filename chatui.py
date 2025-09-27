# -*- coding: utf-8 -*-
"""Terminal chat UI used by both the TLS server and client demos.

The lab pairs network code with a friendly, WhatsApp-inspired interface built
on ``prompt_toolkit``.  This module focuses purely on presentation so that the
TLS files can concentrate on certificate validation, pinning, and MITM flows.
"""

import threading
import textwrap
import shutil
from typing import Callable, List

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, VSplit, Layout, Window
from prompt_toolkit.widgets import TextArea, Label
from prompt_toolkit.styles import Style

def _term_width() -> int:
    """Return a clamped terminal width for consistent bubble rendering.

    Args:
      None.

    Returns:
      int: Width in columns with sensible bounds.

    Raises:
      None.

    Security Notes:
      - None.  Purely visual helper.
    """

    try:
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        cols = 80
    # Limit how wide the bubbles expand so the UI stays legible on large
    # monitors while still adapting to tiny windows.
    return max(40, min(120, cols))


def _wrap_lines(text: str, max_content: int) -> List[str]:
    """Wrap a message into bubble-width chunks preserving whitespace.

    Args:
      text: Text to wrap.
      max_content: Maximum characters per line inside a bubble.

    Returns:
      List[str]: Wrapped lines with whitespace preserved.

    Raises:
      None.

    Security Notes:
      - None.
    """

    return textwrap.wrap(
        text.replace("\t", "    "),
        width=max_content,
        break_long_words=True,
        replace_whitespace=False,
        drop_whitespace=False,
    ) or [""]


def _align_line(line: str, side: str, margin: int = 2) -> str:
    """Pad a string so the bubble appears on the requested side.

    Args:
      line: Text to align.
      side: ``"left"`` or ``"right"`` alignment.
      margin: Margin width in spaces.

    Returns:
      str: Padded string ready for display.

    Raises:
      None.

    Security Notes:
      - None.
    """

    w = _term_width()
    if side == "right":
        pad = max(0, w - len(line) - margin)
        return " " * pad + line
    return " " * margin + line


def make_bubble(text: str, side: str = "left") -> str:
    """Format text using box-drawing characters for chat-style bubbles.

    Args:
      text: Message text.
      side: Which side of the screen to align the bubble to.

    Returns:
      str: Rendered bubble string.

    Raises:
      None.

    Security Notes:
      - None.
    """

    w = _term_width()
    max_content = max(16, min(60, w - 12))  # bubble content width cap
    lines = _wrap_lines(text, max_content)
    inner = max(len(l) for l in lines) if lines else 0
    pad = 1  # inner horizontal padding

    tl, tr, bl, br, h, v = "╭", "╮", "╰", "╯", "─", "│"

    top = tl + h * (inner + 2 * pad) + tr
    bottom = bl + h * (inner + 2 * pad) + br
    middle = [f"{v}{' ' * pad}{l.ljust(inner)}{' ' * pad}{v}" for l in lines or [""]]

    bubble_lines = [top] + middle + [bottom]

    side_align = "right" if side == "right" else "left"
    aligned = [_align_line(line, side_align) for line in bubble_lines]
    return "\n".join(aligned)


def _append_line(area: TextArea, text: str) -> None:
    """Append text to the end of the log while keeping the viewport pinned.

    Args:
      area: Target ``TextArea`` widget.
      text: Text to append.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.
    """

    buf = area.buffer
    buf.cursor_position = len(buf.text)
    if text and not text.endswith("\n"):
        text = text + "\n"
    buf.insert_text(text)
    try:
        w = area.window
        # Force scrollback to follow new messages even when inserted from
        # background threads.
        w.vertical_scroll = max(0, len(buf.text.splitlines()) - 1)
    except Exception:
        pass


def create_chat_app(title_text: str, send_callback: Callable[[str], None]):
    """Build the prompt_toolkit application powering the chat windows.

    Args:
      title_text: Text displayed in the window header.
      send_callback: Callable invoked whenever the user submits a message.

    Returns:
      prompt_toolkit.application.Application: Configured chat UI instance.

    Raises:
      None.

    Security Notes:
      - None.  The UI is deliberately transport-agnostic; it simply relays the
        plaintext that higher layers encrypt or authenticate as needed.
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

    # Thread-safe appenders for background recv threads so UI updates remain
    # atomic relative to network callbacks.
    _lock = threading.Lock()

    def _append_peer(m: str):
        with _lock:
            _append_line(log, make_bubble(m, side="left"))
            _append_line(log, "")
        try:
            app.invalidate()
        except Exception:
            pass

    def _append_sys(m: str):
        with _lock:
            _append_line(log, m)
        try:
            app.invalidate()
        except Exception:
            pass

    app.append_peer = _append_peer     # type: ignore[attr-defined]
    app.append_system = _append_sys    # type: ignore[attr-defined]
    return app

