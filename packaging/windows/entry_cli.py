"""PyInstaller entry point for poisonhound.exe (foreground CLI)."""

import sys

from poisonhound.cli import main

if __name__ == "__main__":
    sys.exit(main())
