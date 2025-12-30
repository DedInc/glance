"""
Command-line interface for Glance with Rich TUI.
Handles user interaction for Java/version selection and launching.

This module now delegates to the cli package for modular implementation.
"""

from cli.main import main

if __name__ == "__main__":
    main()
