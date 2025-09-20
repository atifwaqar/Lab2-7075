# -*- coding: utf-8 -*-
"""Matrix-style terminal animation used for dramatic flair in the launcher.

The animation is intentionally decoupled from the TLS logic, but we still add
docstrings for completeness.  No security-critical code lives here; it simply
displays an effect before the demos start.
"""

import shutil
import time
import math
import time, random
from colorama import Fore, Style
from colorama import Fore, Style
from ui import type_out

# --- Matrix constants & colors ---
BLANK_CHAR = " "
CLEAR_CHAR = "\x1b[H"

STATE_NONE = 0
STATE_FRONT = 1
STATE_TAIL = 2

MIN_LEN = 5
MAX_LEN = 12

BODY_CLRS = [
    "\x1b[38;5;48m",
    "\x1b[38;5;41m",
    "\x1b[38;5;35m",
    "\x1b[38;5;238m",
]
FRONT_CLR = "\x1b[38;5;231m"
TOTAL_CLRS = len(BODY_CLRS)

class Matrix(list):
    """Mutable grid representing the falling characters effect.

    Security Notes:
      - None.  This class is purely cosmetic and does not interact with TLS.
    """

    def __init__(self, wait: int, glitch_freq: int, drop_freq: int):
        """Configure animation timing values.

        Args:
          wait: Base speed of the rain effect.
          glitch_freq: Probability factor for random glitches.
          drop_freq: Probability factor for spawning new drops.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        self.rows = 0
        self.cols = 0
        self.wait = 0.06 / (wait / 100)
        self.glitch_freq = 0.01 / (glitch_freq / 100)
        self.drop_freq = 0.1 * (drop_freq / 100)

    def __str__(self):
        """Render the grid as ANSI-colored text ready for printing.

        Args:
          None.

        Returns:
          str: Full frame representation.

        Raises:
          None.

        Security Notes:
          - None.
        """
        text = ""
        for (c, s, l) in sum(self[MAX_LEN:], []):
            if s == STATE_NONE:
                text += BLANK_CHAR
            elif s == STATE_FRONT:
                text += f"{FRONT_CLR}{c}"
            else:
                text += f"{BODY_CLRS[l]}{c}"
        return text

    def get_prompt_size(self):
        """Return terminal size accounting for safety margin.

        Args:
          None.

        Returns:
          tuple[int, int]: Rows and columns for the animation buffer.

        Raises:
          None.

        Security Notes:
          - None.
        """
        size = shutil.get_terminal_size(fallback=(80, 24))
        return size.lines + MAX_LEN, size.columns

    @staticmethod
    def get_random_char():
        """Return a printable random character for the rain effect.

        Args:
          None.

        Returns:
          str: Single printable character.

        Raises:
          None.

        Security Notes:
          - None.
        """
        return chr(random.randint(32, 126))

    def update_cell(self, r, c, *, char=None, state=None, length=None):
        """Mutate a single cell in the matrix grid.

        Args:
          r: Row index.
          c: Column index.
          char: Optional replacement character.
          state: Optional new state flag.
          length: Optional drop length metadata.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        if char is not None:
            self[r][c][0] = char
        if state is not None:
            self[r][c][1] = state
        if length is not None:
            self[r][c][2] = length

    def fill(self):
        """Initialise the grid with random characters and empty state.

        Args:
          None.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        self[:] = [[[self.get_random_char(), STATE_NONE, 0] for _ in range(self.cols)] for _ in range(self.rows)]

    def apply_glitch(self):
        """Randomly mutate characters to mimic visual glitches.

        Args:
          None.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        total = self.cols * self.rows * self.glitch_freq
        for _ in range(int(total)):
            c = random.randint(0, self.cols - 1)
            r = random.randint(0, self.rows - 1)
            self.update_cell(r, c, char=self.get_random_char())

    def drop_col(self, col):
        """Shift active rain cells down by one row in a column.

        Args:
          col: Column index to update.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        for r in reversed(range(self.rows)):
            _, state, length = self[r][col]
            if state == STATE_NONE:
                continue
            if r != self.rows - 1:
                self.update_cell(r + 1, col, state=state, length=length)
            self.update_cell(r, col, state=STATE_NONE, length=0)

    def add_drop(self, row, col, length):
        """Introduce a new rain drop of ``length`` cells at ``(row, col)``.

        Args:
          row: Starting row index.
          col: Column index.
          length: Number of cells in the drop.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        for i in reversed(range(length)):
            r = row + (length - i)
            if i == 0:
                self.update_cell(r, col, state=STATE_FRONT, length=length)
            else:
                l = math.ceil((TOTAL_CLRS - 1) * i / length)
                self.update_cell(r, col, state=STATE_TAIL, length=l)

    def screen_check(self):
        """Resize the matrix if the terminal dimensions change.

        Args:
          None.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        if (p := self.get_prompt_size()) != (self.rows, self.cols):
            self.rows, self.cols = p
            self.fill()

    def update(self):
        """Advance the simulation by one step.

        Args:
          None.

        Returns:
          None.

        Raises:
          None.

        Security Notes:
          - None.
        """
        for c in range(self.cols):
            self.drop_col(c)
        total = self.cols * self.rows * self.drop_freq
        missing = math.ceil(total / self.cols)
        for _ in range(missing):
            col = random.randint(0, self.cols - 1)
            length = random.randint(MIN_LEN, MAX_LEN)
            self.add_drop(0, col, length)

def matrix_rain_effect(duration=5, speed=120, glitches=80, frequency=100, message="🐇"):
    """Run the Matrix intro animation before launching a demo.

    Args:
      duration: How long to run the animation in seconds.
      speed: Speed parameter for drop updates.
      glitches: Frequency parameter for glitches.
      frequency: Drop spawn frequency parameter.
      message: Optional text revealed during the animation.

    Returns:
      None.

    Raises:
      None.

    Security Notes:
      - None.  Purely aesthetic.
    """
    type_out("Follow the white rabbit.", delay=0.06)
    matrix = Matrix(speed, glitches, frequency)
    end = time.time() + duration

    # figure out where to print the message
    rows, cols = shutil.get_terminal_size(fallback=(80, 40))
    msg_y = rows // 4
    msg_x = (cols - len(message)) // 1 if message else 0
    revealed = 0  # how many chars of the message are revealed

    while time.time() < end:
        print(CLEAR_CHAR, end="")
        print(matrix, end="", flush=True)

        # reveal text when rain reaches the middle
        if message and revealed < len(message):
            for x in range(matrix.cols):
                head_y = None
                # find the head position in this column
                for r in range(matrix.rows):
                    if matrix[r][x][1] == STATE_FRONT:
                        head_y = r
                        break
                if head_y == msg_y and revealed < len(message):
                    # place the next unrevealed character at (msg_y, msg_x+revealed)
                    ch = message[revealed]
                    print(f"\x1b[{msg_y};{msg_x+revealed}H" + Fore.WHITE + ch + Style.RESET_ALL, end="")
                    revealed += 1

        # re-draw already revealed part of message (so it stays visible)
        if message and revealed > 0:
            print(f"\x1b[{msg_y};{msg_x}H" + Fore.WHITE + message[:revealed] + Style.RESET_ALL, end="")

        matrix.screen_check()
        matrix.apply_glitch()
        matrix.update()

        time.sleep(matrix.wait)

    print("\x1b[2J\x1b[H", end="")