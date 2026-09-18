#!/usr/bin/env sh
set -eu
python3 -m pip install --user .
printf '%s\n' 'Установлено. Убедитесь, что ~/.local/bin входит в PATH, затем выполните: safe --help'
