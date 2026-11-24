"""Allow running mcp-shield via `python -m mcp_shield`."""

import sys

from mcp_shield.cli import main

if __name__ == "__main__":
    sys.exit(main())
