"""Entry point for Claude Guard."""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from claude_tool import main

if __name__ == "__main__":
    raise SystemExit(main())
