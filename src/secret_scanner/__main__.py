"""Enable `python -m secret_scanner`."""

from __future__ import annotations

from secret_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
