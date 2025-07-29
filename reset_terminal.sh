#!/bin/bash
# Simple script to reset terminal after TUI corruption
printf '\033c'              # Reset terminal
stty sane                   # Restore sane terminal settings  
tput cnorm                  # Show cursor
tput rmcup                  # Exit alternate screen
printf '\033[?1000l'        # Disable mouse reporting
printf '\033[?1002l'        # Disable mouse tracking
printf '\033[?1003l'        # Disable all mouse events
printf '\033[?1006l'        # Disable SGR mouse mode
printf '\033[?1015l'        # Disable urxvt mouse mode
echo "Terminal reset complete"