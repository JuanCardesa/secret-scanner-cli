"""Render an animated terminal GIF of a `scan local` run for the README.

Reproduces docs/assets/demo.gif from the committed demo terminal report so the
hero image never drifts from real output. Requires Pillow (not a runtime
dependency): `python -m pip install pillow`, then run this module.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

DEMO_DIR = Path(__file__).resolve().parent
ROOT_DIR = DEMO_DIR.parents[1]
TERMINAL_REPORT = DEMO_DIR / "reports" / "example-terminal.txt"
OUTPUT_GIF = ROOT_DIR / "docs" / "assets" / "demo.gif"
FONT_PATH = Path("C:/Windows/Fonts/CascadiaMono.ttf")
FONT_SIZE = 15
COMMAND = "secret-scanner scan local ."
PROMPT_PATH = "~/demo-fixture"

# Fixed palette keeps every frame on the same colors: no inter-frame flicker
# and tight GIF compression.
BG = (11, 14, 20)
WINDOW = (17, 22, 31)
TITLE_BAR = (27, 34, 48)
DOT_RED = (255, 95, 87)
DOT_YELLOW = (254, 188, 46)
DOT_GREEN = (40, 200, 64)
TEXT = (205, 214, 228)
DIM = (123, 138, 160)
SEP = (58, 69, 87)
PROMPT_GREEN = (86, 211, 100)
PROMPT_BLUE = (108, 182, 255)
HIGH = (255, 107, 107)
MEDIUM = (227, 179, 65)
CURSOR = (205, 214, 228)

PALETTE_COLORS = [
    BG,
    WINDOW,
    TITLE_BAR,
    DOT_RED,
    DOT_YELLOW,
    DOT_GREEN,
    TEXT,
    DIM,
    SEP,
    PROMPT_GREEN,
    PROMPT_BLUE,
    HIGH,
    MEDIUM,
    CURSOR,
]

MARGIN = 20
PAD = 22
TITLE_H = 38
LINE_H = 24


def main() -> int:
    lines = [line.rstrip() for line in TERMINAL_REPORT.read_text().splitlines()]
    font = ImageFont.truetype(str(FONT_PATH), FONT_SIZE)
    char_w = font.getlength("M")

    content_cols = max(len(COMMAND) + len(PROMPT_PATH) + 4, *(len(x) for x in lines))
    content_w = int(char_w * content_cols) + 1
    window_w = content_w + PAD * 2
    text_rows = 1 + 1 + len(lines)  # prompt + blank + output
    window_h = TITLE_H + PAD * 2 + text_rows * LINE_H
    size = (window_w + MARGIN * 2, window_h + MARGIN * 2)

    frames: list[Image.Image] = []
    durations: list[int] = []

    # Type the command out.
    for shown in range(0, len(COMMAND) + 1, 2):
        frames.append(_frame(size, font, char_w, COMMAND[:shown], [], cursor=True))
        durations.append(55)
    frames.append(_frame(size, font, char_w, COMMAND, [], cursor=True))
    durations.append(500)

    # Reveal the report line by line.
    for visible in range(1, len(lines) + 1):
        frames.append(_frame(size, font, char_w, COMMAND, lines[:visible]))
        durations.append(150)

    # Hold on the full result, then loop.
    frames.append(_frame(size, font, char_w, COMMAND, lines))
    durations.append(2600)

    palette_img = _palette_image()
    quantized = [
        f.quantize(palette=palette_img, dither=Image.Dither.NONE) for f in frames
    ]

    OUTPUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    quantized[0].save(
        OUTPUT_GIF,
        save_all=True,
        append_images=quantized[1:],
        duration=durations,
        loop=0,
        disposal=2,
        optimize=False,
    )
    kib = OUTPUT_GIF.stat().st_size // 1024
    print(f"Wrote {OUTPUT_GIF.relative_to(ROOT_DIR)} ({kib} KB)")
    return 0


def _frame(
    size: tuple[int, int],
    font: ImageFont.FreeTypeFont,
    char_w: float,
    command_shown: str,
    output_lines: list[str],
    *,
    cursor: bool = False,
) -> Image.Image:
    img = Image.new("RGB", size, BG)
    draw = ImageDraw.Draw(img)

    window = (MARGIN, MARGIN, size[0] - MARGIN, size[1] - MARGIN)
    draw.rounded_rectangle(window, radius=12, fill=WINDOW)
    draw.rounded_rectangle(
        (window[0], window[1], window[2], window[1] + TITLE_H),
        radius=12,
        fill=TITLE_BAR,
    )
    draw.rectangle(
        (window[0], window[1] + TITLE_H - 12, window[2], window[1] + TITLE_H),
        fill=TITLE_BAR,
    )
    cy = window[1] + TITLE_H // 2
    for i, color in enumerate((DOT_RED, DOT_YELLOW, DOT_GREEN)):
        cx = window[0] + 22 + i * 20
        draw.ellipse((cx - 6, cy - 6, cx + 6, cy + 6), fill=color)
    _centered(draw, font, "secret-scanner", window, cy)

    x0 = window[0] + PAD
    y = window[1] + TITLE_H + PAD

    # Prompt line.
    draw.text((x0, y), PROMPT_PATH, font=font, fill=PROMPT_BLUE)
    px = x0 + int(char_w * (len(PROMPT_PATH) + 1))
    draw.text((px, y), "❯", font=font, fill=PROMPT_GREEN)
    cmd_x = px + int(char_w * 2)
    draw.text((cmd_x, y), command_shown, font=font, fill=TEXT)
    if cursor:
        curs_x = cmd_x + int(char_w * len(command_shown))
        draw.rectangle(
            (curs_x, y + 2, curs_x + int(char_w), y + LINE_H - 4), fill=CURSOR
        )

    y += LINE_H * 2
    for line in output_lines:
        _draw_report_line(draw, font, char_w, x0, y, line)
        y += LINE_H

    return img


def _draw_report_line(
    draw: ImageDraw.ImageDraw,
    font: ImageFont.FreeTypeFont,
    char_w: float,
    x0: int,
    y: int,
    line: str,
) -> None:
    if set(line) <= {"-", "+"} and line:
        draw.text((x0, y), line, font=font, fill=SEP)
        return
    if line.startswith("Confidence"):
        draw.text((x0, y), line, font=font, fill=DIM)
        return
    if line.startswith(("high", "medium", "low")):
        word = line.split(" ", 1)[0]
        color = {"high": HIGH, "medium": MEDIUM, "low": PROMPT_BLUE}[word]
        draw.text((x0, y), word, font=font, fill=color)
        rest_x = x0 + int(char_w * len(word))
        draw.text((rest_x, y), line[len(word) :], font=font, fill=TEXT)
        return
    if "found." in line:
        draw.text((x0, y), line, font=font, fill=HIGH)
        return
    draw.text((x0, y), line, font=font, fill=TEXT)


def _centered(
    draw: ImageDraw.ImageDraw,
    font: ImageFont.FreeTypeFont,
    text: str,
    window: tuple[int, int, int, int],
    cy: int,
) -> None:
    width = draw.textlength(text, font=font)
    x = window[0] + (window[2] - window[0] - width) / 2
    draw.text((x, cy - FONT_SIZE / 2 - 1), text, font=font, fill=DIM)


def _palette_image() -> Image.Image:
    flat: list[int] = []
    for color in PALETTE_COLORS:
        flat.extend(color)
    flat.extend(PALETTE_COLORS[0] * (256 - len(PALETTE_COLORS)))
    palette_img = Image.new("P", (1, 1))
    palette_img.putpalette(flat)
    return palette_img


if __name__ == "__main__":
    raise SystemExit(main())
