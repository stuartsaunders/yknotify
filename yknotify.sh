#!/bin/bash

# Ensure Homebrew binaries (jq, terminal-notifier) are available under launchd
export PATH="/opt/homebrew/bin:$PATH"

# List of sounds: https://apple.stackexchange.com/a/479714

FIFO="/var/run/yknotify.fifo"
ICON="/usr/local/share/yknotify/yubikey.png"

while true; do
  # Wait for the FIFO to exist (daemon may not have started yet)
  while [[ ! -p "$FIFO" ]]; do
    sleep 1
  done

  # Read events from the FIFO; loop exits on EOF (daemon restart / FIFO broken)
  while IFS= read -r line; do

    # Send notification
    message="$(echo "$line" | jq -r '.type')"
    if command -v terminal-notifier >/dev/null 2>&1; then
      terminal-notifier \
        -group "yknotify" \
        -title "yknotify" \
        -message "$message" \
        -contentImage "$ICON" \
        -sound "waiting"
    else
      osascript -e "display notification \"$message\" with title \"yknotify\""
    fi

  done < "$FIFO"

  # Reader got EOF — daemon probably restarted; retry after a short pause
  sleep 1
done
