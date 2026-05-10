#!/bin/bash

APP_NAME=AmneziaVPN
PLIST_NAME=$APP_NAME.plist
LAUNCH_DAEMONS_PLIST_NAME="/Library/LaunchDaemons/$PLIST_NAME"

# Keep upgrade cleanup deliberately narrow. The package payload should atomically
# replace the app bundle; this script only stops running processes and removes
# the old service registration.
if pgrep -x "$APP_NAME" > /dev/null; then
    echo "Quitting $APP_NAME..."
    osascript -e 'tell application "'"$APP_NAME"'" to quit' || true
    for i in {1..10}; do
        if ! pgrep -x "$APP_NAME" > /dev/null; then
            break
        fi
        sleep 1
    done
fi

if pgrep -x "${APP_NAME}-service" > /dev/null; then
    killall -9 "${APP_NAME}-service" || true
fi

if launchctl list "${APP_NAME}-service" > /dev/null 2>&1; then
    launchctl bootout system "$LAUNCH_DAEMONS_PLIST_NAME" || launchctl unload "$LAUNCH_DAEMONS_PLIST_NAME" || true
fi
rm -f "$LAUNCH_DAEMONS_PLIST_NAME"
