"""Offline, optional terminal playback of the bundled NOXTRACE intro."""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

FRAME_MARKER = "\n\x1eNOXTRACE_FRAME\x1f\n"


def load_intro_frames(path: Path | None = None) -> list[str]:
    """Load pre-rendered truecolor terminal frames; no image library is needed."""
    frame_path = path or Path(__file__).with_name("intro_frames.ansi")
    content = frame_path.read_text(encoding="utf-8")
    frames = [frame for frame in content.split(FRAME_MARKER) if frame.strip()]
    if not frames:
        raise ValueError(f"No intro frames found in {frame_path}")
    return frames


def play_intro(frame_delay: float = 0.095) -> bool:
    """Play the splash once in an interactive terminal. Return False on Ctrl+C."""
    if (
        not sys.stdout.isatty()
        or os.environ.get("NOXTRACE_NO_INTRO") == "1"
        or "NO_COLOR" in os.environ
        or os.environ.get("TERM", "") == "dumb"
    ):
        return True

    # A narrow terminal would wrap the pre-rendered rows and corrupt the animation.
    columns = shutil.get_terminal_size((80, 24)).columns
    if columns < 80:
        return True

    try:
        frames = load_intro_frames()
    except (OSError, ValueError):
        # The intro is decorative; a missing asset must never stop the core CLI.
        return True

    blue = "\033[38;2;96;165;250m"
    white = "\033[97m"
    gray = "\033[38;2;148;163;184m"
    reset = "\033[0m"
    header = (
        f"{blue}{white} NOXTRACE {reset}{blue} // SYSTEM BOOT SEQUENCE "
        f"{gray}:: MULTI-ENGINE WORKBENCH{reset}\n"
    )
    footer = f"\n{gray}  SIGNALS ALIGNED  //  MODULES STANDING BY  //  TRACE RESPONSIBLY{reset}\n"

    try:
        for frame in frames:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(header)
            sys.stdout.write(frame)
            sys.stdout.write(footer)
            sys.stdout.flush()
            time.sleep(max(0.0, frame_delay))
    except KeyboardInterrupt:
        sys.stdout.write(reset + "\033[2J\033[H")
        sys.stdout.flush()
        return False

    sys.stdout.write(reset + "\033[2J\033[H")
    sys.stdout.flush()
    return True
