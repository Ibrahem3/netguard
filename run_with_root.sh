#!/bin/bash
# Script to run the application with root privileges required for network monitoring
exec > >(tee -i /tmp/netguard.log)
exec 2>&1
echo "Starting NetGuard launcher at $(date)"
echo "User: $USER, EUID: $EUID"

# Get the absolute path of the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
APP_PATH="$SCRIPT_DIR/build/linux/x64/release/bundle/linuxtemp"

if [ ! -f "$APP_PATH" ]; then
  echo "Error: Application binary not found at $APP_PATH"
  echo "Please run 'flutter build linux --debug' first."
  exit 1
fi

if [ "$EUID" -eq 0 ]; then
  # We are running as root
  echo "Running as root..."
  "$APP_PATH"
else
  # We are not root, request elevation
  # Retain environment variables needed for GUI
  echo "Requesting root privileges..."
  if command -v sudo >/dev/null 2>&1; then
      # Try sudo first (likely to have NOPASSWD configured)
      sudo -E "$0" "$@"
  else
      # Fallback to pkexec
      pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY "$0" "$@"
  fi
fi
