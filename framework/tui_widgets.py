from __future__ import annotations

import curses
import textwrap
from typing import Iterable


# ---------------------------------------------------------------------------
# Color profiles
# ---------------------------------------------------------------------------

COLOR_PROFILES = {
    "MONO": {
        "fg": curses.COLOR_WHITE,
        "bg": curses.COLOR_BLACK,
        "accent": curses.COLOR_WHITE,
        "dim": curses.COLOR_WHITE,
        "success": curses.COLOR_WHITE,
        "warning": curses.COLOR_WHITE,
        "error": curses.COLOR_WHITE,
        "selection_fg": curses.COLOR_BLACK,
        "selection_bg": curses.COLOR_WHITE,
    },

    "HIGH CONTRAST": {
        "fg": curses.COLOR_WHITE,
        "bg": curses.COLOR_BLACK,
        "accent": curses.COLOR_WHITE,
        "dim": curses.COLOR_WHITE,
        "success": curses.COLOR_WHITE,
        "warning": curses.COLOR_WHITE,
        "error": curses.COLOR_WHITE,
        "selection_fg": curses.COLOR_BLACK,
        "selection_bg": curses.COLOR_WHITE,
    },

    "INVERTED": {
        "fg": curses.COLOR_BLACK,
        "bg": curses.COLOR_WHITE,
        "accent": curses.COLOR_BLACK,
        "dim": curses.COLOR_BLACK,
        "success": curses.COLOR_BLACK,
        "warning": curses.COLOR_BLACK,
        "error": curses.COLOR_BLACK,
        "selection_fg": curses.COLOR_WHITE,
        "selection_bg": curses.COLOR_BLACK,
    },

    "AMBER": {
        "fg": curses.COLOR_YELLOW,
        "bg": curses.COLOR_BLACK,
        "accent": curses.COLOR_YELLOW,
        "dim": curses.COLOR_YELLOW,
        "success": curses.COLOR_YELLOW,
        "warning": curses.COLOR_YELLOW,
        "error": curses.COLOR_YELLOW,
        "selection_fg": curses.COLOR_BLACK,
        "selection_bg": curses.COLOR_YELLOW,
    },

    "GREEN": {
        "fg": curses.COLOR_GREEN,
        "bg": curses.COLOR_BLACK,
        "accent": curses.COLOR_GREEN,
        "dim": curses.COLOR_GREEN,
        "success": curses.COLOR_GREEN,
        "warning": curses.COLOR_GREEN,
        "error": curses.COLOR_GREEN,
        "selection_fg": curses.COLOR_BLACK,
        "selection_bg": curses.COLOR_GREEN,
    },

    "CYAN": {
        "fg": curses.COLOR_CYAN,
        "bg": curses.COLOR_BLACK,
        "accent": curses.COLOR_CYAN,
        "dim": curses.COLOR_CYAN,
        "success": curses.COLOR_CYAN,
        "warning": curses.COLOR_CYAN,
        "error": curses.COLOR_CYAN,
        "selection_fg": curses.COLOR_BLACK,
        "selection_bg": curses.COLOR_CYAN,
    },
}


CURRENT_PROFILE = "MONO"


# Pair IDs
PAIR_NORMAL = 1
PAIR_ACCENT = 2
PAIR_DIM = 3
PAIR_SUCCESS = 4
PAIR_WARNING = 5
PAIR_ERROR = 6
PAIR_SELECTED = 7

def init_colors(profile="MONO"):
    curses.start_color()

    # DO NOT inherit Kitty's terminal palette.
    # Explicitly define our own colors.
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLACK)

    # Selected item = black text on white background.
    curses.init_pair(
        7,
        curses.COLOR_BLACK,
        curses.COLOR_WHITE,
    )


def setup_screen(stdscr):
    stdscr.bkgd(" ", curses.color_pair(PAIR_NORMAL))
    stdscr.erase()

    h, w = stdscr.getmaxyx()

    for y in range(h):
        try:
            stdscr.addstr(
                y,
                0,
                " " * w,
                curses.color_pair(PAIR_NORMAL),
            )
        except curses.error:
            pass

    stdscr.refresh()


# ---------------------------------------------------------------------------
# Safe drawing helpers
# ---------------------------------------------------------------------------

def safe_addstr(
    stdscr,
    y: int,
    x: int,
    text: str,
    attr: int = 0,
):
    """
    Draw text without allowing curses to crash when the text reaches
    the terminal edge.
    """

    h, w = stdscr.getmaxyx()

    if y < 0 or y >= h:
        return

    if x < 0:
        text = text[-x:]
        x = 0

    if x >= w:
        return

    text = str(text)
    text = text[: max(0, w - x)]

    if not text:
        return

    try:
        stdscr.addstr(y, x, text, attr)
    except curses.error:
        pass


def safe_hline(
    stdscr,
    y: int,
    x: int,
    width: int,
    char: str = "─",
    attr: int = 0,
):
    h, w = stdscr.getmaxyx()

    if y < 0 or y >= h:
        return

    width = min(width, w - x)

    if width <= 0:
        return

    try:
        stdscr.addstr(y, x, char * width, attr)
    except curses.error:
        pass


# ---------------------------------------------------------------------------
# Header / footer
# ---------------------------------------------------------------------------

def draw_header(
    stdscr,
    title: str,
    subtitle: str | None = None,
):
    h, w = stdscr.getmaxyx()

    safe_addstr(
        stdscr,
        0,
        0,
        " " * max(0, w),
        curses.color_pair(PAIR_NORMAL),
    )

    safe_addstr(
        stdscr,
        1,
        2,
        "V1.1",
        curses.color_pair(PAIR_ACCENT) | curses.A_BOLD,
    )

    safe_addstr(
        stdscr,
        1,
        10,
        "//",
        curses.color_pair(PAIR_DIM),
    )

    safe_addstr(
        stdscr,
        1,
        13,
        title.upper(),
        curses.color_pair(PAIR_NORMAL) | curses.A_BOLD,
    )

    if subtitle:
        subtitle = str(subtitle)
        available = max(0, w - 35)
        subtitle = subtitle[:available]

        safe_addstr(
            stdscr,
            1,
            max(30, w - len(subtitle) - 2),
            subtitle,
            curses.color_pair(PAIR_DIM),
        )

    safe_hline(
        stdscr,
        2,
        2,
        max(0, w - 4),
        "═",
        curses.color_pair(PAIR_ACCENT),
    )


def draw_footer(
    stdscr,
    text: str = "↑/↓ navigate   ENTER select   Q back",
):
    h, w = stdscr.getmaxyx()

    safe_hline(
        stdscr,
        h - 3,
        2,
        max(0, w - 4),
        "─",
        curses.color_pair(PAIR_DIM),
    )

    safe_addstr(
        stdscr,
        h - 2,
        2,
        text,
        curses.color_pair(PAIR_DIM),
    )


# ---------------------------------------------------------------------------
# Panels
# ---------------------------------------------------------------------------

def draw_panel(
    stdscr,
    y: int,
    x: int,
    height: int,
    width: int,
    title: str = "",
    lines: Iterable[str] | None = None,
    attr: int = 0,
):
    if height < 3 or width < 4:
        return

    lines = list(lines or [])

    normal = curses.color_pair(PAIR_NORMAL) | attr
    accent = curses.color_pair(PAIR_ACCENT) | curses.A_BOLD

    # Top
    title_text = f" {title} " if title else ""

    if title_text:
        title_text = title_text[: max(0, width - 4)]

    top_remaining = max(0, width - 2 - len(title_text))

    safe_addstr(
        stdscr,
        y,
        x,
        "┌" + title_text + "─" * top_remaining + "┐",
        accent,
    )

    # Content
    content_height = height - 2

    for row in range(content_height):
        text = lines[row] if row < len(lines) else ""
        text = str(text)

        max_text = max(0, width - 4)
        text = text[:max_text]

        safe_addstr(
            stdscr,
            y + row + 1,
            x,
            "│",
            normal,
        )

        safe_addstr(
            stdscr,
            y + row + 1,
            x + 2,
            text.ljust(max_text),
            normal,
        )

        safe_addstr(
            stdscr,
            y + row + 1,
            x + width - 1,
            "│",
            normal,
        )

    # Bottom
    safe_addstr(
        stdscr,
        y + height - 1,
        x,
        "└" + "─" * (width - 2) + "┘",
        accent,
    )


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def menu(
    stdscr,
    title: str,
    options: list[str],
    subtitle: str = "",
    footer: str = "↑/↓ move   Enter select   q back",
):
    """
    Full-screen navigable menu.

    Returns:
        selected index
        -1 on q / ESC
    """

    if not options:
        return -1

    selected = 0
    top = 0

    while True:
        stdscr.erase()
        setup_screen(stdscr)

        h, w = stdscr.getmaxyx()

        draw_header(stdscr, title, subtitle)

        panel_x = 3
        panel_y = 4
        panel_w = max(30, w - 6)
        panel_h = max(7, min(h - 8, len(options) + 4))

        visible_count = panel_h - 4

        if selected < top:
            top = selected

        if selected >= top + visible_count:
            top = selected - visible_count + 1

        visible = options[top:top + visible_count]

        draw_panel(
            stdscr,
            panel_y,
            panel_x,
            panel_h,
            panel_w,
            f" {title.upper()} ",
        )

        for i, option in enumerate(visible):
            real_index = top + i
            y = panel_y + 2 + i

            is_selected = real_index == selected

            text = str(option)
            text = text[: panel_w - 8]

            if is_selected:
                prefix = "  ▸ "
                attr = curses.color_pair(PAIR_SELECTED) | curses.A_BOLD

                safe_addstr(
                    stdscr,
                    y,
                    panel_x + 2,
                    " " * (panel_w - 4),
                    attr,
                )

                safe_addstr(
                    stdscr,
                    y,
                    panel_x + 3,
                    prefix + text,
                    attr,
                )
            else:
                prefix = "    "
                attr = curses.color_pair(PAIR_NORMAL)

                safe_addstr(
                    stdscr,
                    y,
                    panel_x + 3,
                    prefix + text,
                    attr,
                )

        if top > 0:
            safe_addstr(
                stdscr,
                panel_y + 1,
                panel_x + panel_w - 5,
                " ▲ ",
                curses.color_pair(PAIR_DIM),
            )

        if top + visible_count < len(options):
            safe_addstr(
                stdscr,
                panel_y + panel_h - 2,
                panel_x + panel_w - 5,
                " ▼ ",
                curses.color_pair(PAIR_DIM),
            )

        draw_footer(stdscr, footer)

        stdscr.refresh()

        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            return -1

        if key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(options)

        elif key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(options)

        elif key in (curses.KEY_HOME,):
            selected = 0

        elif key in (curses.KEY_END,):
            selected = len(options) - 1

        elif key in (10, 13, curses.KEY_ENTER):
            return selected


# ---------------------------------------------------------------------------
# Checklist
# ---------------------------------------------------------------------------

def checklist(
    stdscr,
    title: str,
    labels: list[str],
    selected: set[int] | None = None,
):
    selected = set(selected or set())
    cursor = 0
    top = 0

    if not labels:
        return selected

    while True:
        stdscr.erase()
        setup_screen(stdscr)

        h, w = stdscr.getmaxyx()

        draw_header(
            stdscr,
            title,
            f"{len(selected)} selected",
        )

        panel_x = 3
        panel_y = 4
        panel_w = max(40, w - 6)
        panel_h = max(8, h - 8)

        visible_count = panel_h - 4

        if cursor < top:
            top = cursor

        if cursor >= top + visible_count:
            top = cursor - visible_count + 1

        draw_panel(
            stdscr,
            panel_y,
            panel_x,
            panel_h,
            panel_w,
            " PORTS / SERVICES ",
        )

        for i, label in enumerate(
            labels[top:top + visible_count]
        ):
            index = top + i
            y = panel_y + 2 + i

            checked = index in selected
            focused = index == cursor

            marker = "[X]" if checked else "[ ]"
            text = f"{marker} {label}"

            if focused:
                attr = curses.color_pair(PAIR_SELECTED) | curses.A_BOLD

                safe_addstr(
                    stdscr,
                    y,
                    panel_x + 2,
                    " " * (panel_w - 4),
                    attr,
                )
            else:
                attr = curses.color_pair(PAIR_NORMAL)

            safe_addstr(
                stdscr,
                y,
                panel_x + 3,
                text[:panel_w - 6],
                attr,
            )

        draw_footer(
            stdscr,
            "↑/↓ move   SPACE toggle   ENTER apply   q cancel",
        )

        stdscr.refresh()

        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            return None

        if key in (curses.KEY_UP, ord("k")):
            cursor = (cursor - 1) % len(labels)

        elif key in (curses.KEY_DOWN, ord("j")):
            cursor = (cursor + 1) % len(labels)

        elif key == ord(" "):
            if cursor in selected:
                selected.remove(cursor)
            else:
                selected.add(cursor)

        elif key in (10, 13, curses.KEY_ENTER):
            return selected


# ---------------------------------------------------------------------------
# Text input
# ---------------------------------------------------------------------------

def text_input(
    stdscr,
    prompt: str,
    initial: str = "",
    help_line: str = "",
):
    h, w = stdscr.getmaxyx()

    value = initial or ""
    cursor = len(value)

    while True:
        stdscr.erase()
        setup_screen(stdscr)

        draw_header(stdscr, "Input")

        box_w = min(w - 6, max(50, len(prompt) + 20))
        box_x = max(3, (w - box_w) // 2)
        box_y = max(5, h // 2 - 3)

        draw_panel(
            stdscr,
            box_y,
            box_x,
            7,
            box_w,
            " INPUT ",
        )

        safe_addstr(
            stdscr,
            box_y + 2,
            box_x + 3,
            prompt[:box_w - 6],
            curses.color_pair(PAIR_ACCENT) | curses.A_BOLD,
        )

        input_width = box_w - 6
        visible_value = value

        if len(visible_value) > input_width:
            start = max(
                0,
                cursor - input_width + 1,
            )
            visible_value = visible_value[start:start + input_width]

        safe_addstr(
            stdscr,
            box_y + 4,
            box_x + 3,
            visible_value.ljust(input_width),
            curses.color_pair(PAIR_NORMAL),
        )

        if help_line:
            safe_addstr(
                stdscr,
                box_y + 5,
                box_x + 3,
                help_line[:box_w - 6],
                curses.color_pair(PAIR_DIM),
            )

        draw_footer(
            stdscr,
            "ENTER accept   ESC/q cancel   ←/→ edit",
        )

        stdscr.refresh()

        try:
            curses.curs_set(1)
        except curses.error:
            pass

        key = stdscr.getch()

        if key in (27,):
            curses.curs_set(0)
            return None

        if key in (10, 13, curses.KEY_ENTER):
            curses.curs_set(0)
            return value

        if key == curses.KEY_LEFT:
            cursor = max(0, cursor - 1)

        elif key == curses.KEY_RIGHT:
            cursor = min(len(value), cursor + 1)

        elif key == curses.KEY_HOME:
            cursor = 0

        elif key == curses.KEY_END:
            cursor = len(value)

        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cursor > 0:
                value = value[:cursor - 1] + value[cursor:]
                cursor -= 1

        elif key == curses.KEY_DC:
            if cursor < len(value):
                value = value[:cursor] + value[cursor + 1:]

        elif 32 <= key <= 126:
            value = value[:cursor] + chr(key) + value[cursor:]
            cursor += 1


# ---------------------------------------------------------------------------
# Scrollable text
# ---------------------------------------------------------------------------

def scrollable_text(
    stdscr,
    title: str,
    lines: list[str],
    subtitle: str = "",
):
    offset = 0

    normalized = []

    for line in lines:
        if line is None:
            normalized.append("")
            continue

        normalized.extend(
            textwrap.wrap(
                str(line),
                width=max(20, stdscr.getmaxyx()[1] - 8),
                replace_whitespace=False,
                drop_whitespace=False,
            ) or [""]
        )

    while True:
        stdscr.erase()
        setup_screen(stdscr)

        h, w = stdscr.getmaxyx()

        draw_header(
            stdscr,
            title,
            subtitle,
        )

        panel_x = 2
        panel_y = 4
        panel_w = w - 4
        panel_h = h - 8

        draw_panel(
            stdscr,
            panel_y,
            panel_x,
            panel_h,
            panel_w,
            " OUTPUT ",
        )

        visible = panel_h - 3

        max_offset = max(
            0,
            len(normalized) - visible,
        )

        offset = min(offset, max_offset)

        for i, line in enumerate(
            normalized[offset:offset + visible]
        ):
            safe_addstr(
                stdscr,
                panel_y + 2 + i,
                panel_x + 3,
                line[:panel_w - 6],
                curses.color_pair(PAIR_NORMAL),
            )

        if offset > 0:
            safe_addstr(
                stdscr,
                panel_y + 1,
                panel_x + panel_w - 7,
                " ▲ ",
                curses.color_pair(PAIR_DIM),
            )

        if offset < max_offset:
            safe_addstr(
                stdscr,
                panel_y + panel_h - 2,
                panel_x + panel_w - 7,
                " ▼ ",
                curses.color_pair(PAIR_DIM),
            )

        draw_footer(
            stdscr,
            "↑/↓ scroll   PgUp/PgDn page   Home/End   q/ESC back",
        )

        stdscr.refresh()

        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            return

        if key in (curses.KEY_UP, ord("k")):
            offset = max(0, offset - 1)

        elif key in (curses.KEY_DOWN, ord("j")):
            offset = min(max_offset, offset + 1)

        elif key == curses.KEY_PPAGE:
            offset = max(0, offset - visible)

        elif key == curses.KEY_NPAGE:
            offset = min(max_offset, offset + visible)

        elif key == curses.KEY_HOME:
            offset = 0

        elif key == curses.KEY_END:
            offset = max_offset


# ---------------------------------------------------------------------------
# Message / confirmation boxes
# ---------------------------------------------------------------------------

def message_box(
    stdscr,
    title: str,
    lines: list[str],
):
    h, w = stdscr.getmaxyx()

    wrapped = []

    for line in lines:
        wrapped.extend(
            textwrap.wrap(
                str(line),
                width=max(20, w - 16),
            ) or [""]
        )

    box_w = min(
        w - 6,
        max(
            40,
            max(
                [len(x) for x in wrapped] + [len(title) + 8]
            ) + 8,
        ),
    )

    box_h = min(
        h - 6,
        max(6, len(wrapped) + 5),
    )

    box_x = max(3, (w - box_w) // 2)
    box_y = max(3, (h - box_h) // 2)

    stdscr.erase()
    setup_screen(stdscr)

    draw_panel(
        stdscr,
        box_y,
        box_x,
        box_h,
        box_w,
        f" {title.upper()} ",
    )

    for i, line in enumerate(wrapped[:box_h - 4]):
        safe_addstr(
            stdscr,
            box_y + 2 + i,
            box_x + 3,
            line[:box_w - 6],
            curses.color_pair(PAIR_NORMAL),
        )

    draw_footer(
        stdscr,
        "ENTER / any key to continue",
    )

    stdscr.refresh()
    stdscr.getch()


def confirm(
    stdscr,
    question: str,
):
    h, w = stdscr.getmaxyx()

    box_w = min(
        w - 6,
        max(50, len(question) + 10),
    )

    box_h = 8
    box_x = max(3, (w - box_w) // 2)
    box_y = max(3, (h - box_h) // 2)

    selected = 0

    while True:
        stdscr.erase()
        setup_screen(stdscr)

        draw_panel(
            stdscr,
            box_y,
            box_x,
            box_h,
            box_w,
            " CONFIRM ",
        )

        safe_addstr(
            stdscr,
            box_y + 2,
            box_x + 3,
            question[:box_w - 6],
            curses.color_pair(PAIR_NORMAL),
        )

        options = ["YES", "NO"]

        for i, option in enumerate(options):
            x = box_x + 8 + i * 12

            if i == selected:
                attr = curses.color_pair(PAIR_SELECTED) | curses.A_BOLD
            else:
                attr = curses.color_pair(PAIR_NORMAL)

            safe_addstr(
                stdscr,
                box_y + 5,
                x,
                f" {option} ",
                attr,
            )

        draw_footer(
            stdscr,
            "←/→ select   ENTER confirm   q cancel",
        )

        stdscr.refresh()

        key = stdscr.getch()

        if key in (ord("q"), ord("Q"), 27):
            return False

        if key in (
            curses.KEY_LEFT,
            curses.KEY_RIGHT,
            ord("h"),
            ord("l"),
        ):
            selected = 1 - selected

        elif key in (10, 13, curses.KEY_ENTER):
            return selected == 0
