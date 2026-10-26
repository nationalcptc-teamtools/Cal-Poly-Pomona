#!/usr/bin/env python3
"""Single entry point. All the real code lives in the core/ package."""
import sys

from core.cli import main

if __name__ == "__main__":
    sys.exit(main())
