#!/bin/zsh
cd "$(dirname "$0")"
(sleep 2 && open http://127.0.0.1:8790) &
exec /usr/bin/python3 monitor.py
