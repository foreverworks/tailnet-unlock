"""Run the command line: python3 -m tailnet_unlock."""

import sys

from tailnet_unlock.cli import main

sys.exit(main(sys.argv[1:]))
