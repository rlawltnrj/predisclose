"""
Render docs/demo.gif from a real predisclose run against live public data.

The command is "typed", then the real terminal output appears. The output comes from
run_check() and to_terminal(), the same code the CLI uses, with two differences from a
default run: at most 2 matches are listed per section (the CLI lists 5), and only the table,
the public-record section and the closing disclaimer are shown.

Data is live and fonts differ per OS, so a rerun is not byte-for-byte identical. The run
bypasses the local cache. The script stops without writing if any check errored or was skipped.

Usage:  GITHUB_TOKEN=... uv run --no-project --with pillow --with-editable . \\
            python scripts/demo_gif.py [out.gif]
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from rich.color import ColorType
from rich.console import Console
from rich.text import Text

from predisclose.core import run_check
from predisclose.http import Http, github_token_from_env
from predisclose.models import Finding
from predisclose.output import to_terminal

COMMAND = "predisclose check --pkg pypi:jinja2 --version 2.10 --cwe CWE-693 --file sandbox.py"
FINDING = Finding(ecosystem="PyPI", package="jinja2", version="2.10", cwe=["CWE-693"], files=["sandbox.py"])
COLS = 96
FONT_SIZE = 15
PAD = 18
BG = (24, 26, 33)
FG = (220, 223, 228)
DIM = (128, 133, 145)
PROMPT = (110, 200, 140)
FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/Library/Fonts/Menlo.ttc",
    "C:/Windows/Fonts/consola.ttf",
]
# The 16 standard terminal colors, softened for a dark background.
ANSI16 = [
    (60, 63, 72), (240, 113, 120), (140, 210, 140), (230, 200, 110),
    (120, 160, 240), (200, 140, 220), (110, 200, 220), (220, 223, 228),
    (110, 115, 128), (255, 140, 140), (160, 230, 160), (245, 220, 130),
    (150, 180, 250), (220, 160, 235), (140, 220, 235), (245, 246, 248),
]

Run = tuple[str, tuple[int, int, int], bool]


def _color(style) -> tuple[int, int, int]:
    if style is None:
        return FG
    if style.dim:
        return DIM  # dim wins over hue, as in most terminals' default themes
    color = style.color
    if color is None or color.type == ColorType.DEFAULT:
        return FG
    if color.number is not None and color.number < 16:
        return ANSI16[color.number]
    return tuple(color.get_truecolor())


def capture() -> list[list[Run]]:
    """Run the check and return the output as lines of (text, color, bold) runs."""
    http = Http(use_cache=False, token=github_token_from_env())
    try:
        report = run_check(http, FINDING)
    finally:
        http.close()
    bad = [r for r in report.results if r.status in ("error", "skipped")]
    if bad:
        raise SystemExit("not writing a demo of a failed run: " + "; ".join(f"{r.check}: {r.summary}" for r in bad))

    buf = io.StringIO()
    console = Console(file=buf, width=COLS, force_terminal=True, color_system="truecolor")
    to_terminal(report, console, max_evidence=2)
    lines: list[list[Run]] = []
    for line in Text.from_ansi(buf.getvalue()).split("\n", allow_blank=True):
        runs: list[Run] = []
        for seg in line.render(console):
            if seg.text:
                runs.append((seg.text, _color(seg.style), bool(seg.style and seg.style.bold)))
        lines.append(runs)

    # Keep the table and the public-record section, then the closing disclaimer.
    def text(line: list[Run]) -> str:
        return "".join(t for t, _, _ in line)

    headings = [i for i, line in enumerate(lines) if text(line) in ("Public fix", "Recent activity", "Where to report")]
    disclaimer = next((i for i, line in enumerate(lines) if text(line).startswith("No public record does not")), None)
    if headings and disclaimer is not None and headings[0] < disclaimer:
        lines = lines[: headings[0]] + lines[disclaimer:]
    while lines and not lines[-1]:
        lines.pop()
    return lines


def load_font(bold: bool = False) -> ImageFont.FreeTypeFont:
    for path in FONT_PATHS:
        for p in ((path.replace(".ttf", "-Bold.ttf"), path) if bold else (path,)):
            if Path(p).exists():
                return ImageFont.truetype(p, FONT_SIZE)
    raise SystemExit("no monospace font found; edit FONT_PATHS")


def _box(ch: str) -> tuple[str, int] | None:
    """Sides a box-drawing character connects (u, d, l, r) and its line width."""
    light = {"─": "lr", "│": "ud", "┌": "dr", "┐": "dl", "└": "ur", "┘": "ul",
             "├": "udr", "┤": "udl", "┬": "dlr", "┴": "ulr", "┼": "udlr"}
    heavy = {"━": "lr", "┃": "ud", "┏": "dr", "┓": "dl", "┗": "ur", "┛": "ul",
             "┣": "udr", "┫": "udl", "┳": "dlr", "┻": "ulr", "╋": "udlr",
             "┡": "udr", "┩": "udl", "╇": "udlr"}
    if ch in light:
        return light[ch], 1
    if ch in heavy:
        return heavy[ch], 2
    return None


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/demo.gif")
    output = capture()
    font, bold_font = load_font(), load_font(bold=True)
    cell_w = font.getlength("M")
    cell_h = int(FONT_SIZE * 1.35)
    rows = len(output) + 3
    size = (int(PAD * 2 + cell_w * COLS) + 1, PAD * 2 + cell_h * rows)

    def x_at(col: int) -> int:
        return round(PAD + col * cell_w)

    def draw_line(draw: ImageDraw.ImageDraw, row_y: int, runs: list[Run]) -> None:
        col = 0
        for text, color, bold in runs:
            for ch in text:
                box = _box(ch)
                x0, x1 = x_at(col), x_at(col + 1)
                if box:  # draw borders edge to edge so they join without gaps
                    sides, w = box
                    cx, cy = (x0 + x1) // 2, row_y + cell_h // 2
                    if "l" in sides:
                        draw.line([(x0, cy), (cx, cy)], fill=color, width=w)
                    if "r" in sides:
                        draw.line([(cx, cy), (x1, cy)], fill=color, width=w)
                    if "u" in sides:
                        draw.line([(cx, row_y), (cx, cy)], fill=color, width=w)
                    if "d" in sides:
                        draw.line([(cx, cy), (cx, row_y + cell_h)], fill=color, width=w)
                elif ch != " ":
                    draw.text((x0, row_y), ch, font=bold_font if bold else font, fill=color)
                col += 1

    def frame(typed: str, shown: int, cursor: bool) -> Image.Image:
        img = Image.new("RGB", size, BG)
        draw = ImageDraw.Draw(img)
        y = PAD
        draw.text((PAD, y), "$ ", font=font, fill=PROMPT)
        draw.text((x_at(2), y), typed, font=font, fill=FG)
        if cursor:
            x = x_at(2 + len(typed))
            draw.rectangle([x, y + 2, x + int(cell_w) - 1, y + cell_h - 4], fill=FG)
        y += cell_h * 2
        for line in output[:shown]:
            draw_line(draw, y, line)
            y += cell_h
        return img

    frames: list[Image.Image] = []
    durations: list[int] = []  # GIF stores delays in 10 ms steps
    for i in range(0, len(COMMAND) + 1, 3):  # typing
        frames.append(frame(COMMAND[:i], 0, True))
        durations.append(40)
    frames.append(frame(COMMAND, 0, False))
    durations.append(900)  # "running"
    for shown in range(1, len(output) + 1):  # output streams in
        frames.append(frame(COMMAND, shown, False))
        durations.append(60)
    durations[-1] = 6000  # hold the result

    # One palette for every frame, taken from the last (it has every color), keeps colors exact.
    shared = frames[-1].quantize(colors=64)
    palette = [f.quantize(palette=shared, dither=Image.Dither.NONE) for f in frames]
    out.parent.mkdir(parents=True, exist_ok=True)
    palette[0].save(out, save_all=True, append_images=palette[1:], duration=durations, loop=0, optimize=True)
    print(f"wrote {out} ({out.stat().st_size // 1024} KiB, {len(frames)} frames, {size[0]}x{size[1]})")


if __name__ == "__main__":
    main()
