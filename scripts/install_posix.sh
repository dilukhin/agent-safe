#!/usr/bin/env sh
set -eu
python3 -m pip install --user -e .
printf '%s\n' 'Installed. Make sure ~/.local/bin is in PATH, then run: safe --help'
