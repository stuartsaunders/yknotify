<div align="center">
  <kbd>
    <img src="notification.png" width="500px"/>
  </kbd>
</div>
<br/>

> **Fork of [noperator/yknotify](https://github.com/noperator/yknotify).** The original runs as a single LaunchAgent, which requires the user to have persistent admin group membership because `log stream` needs it. This fork splits into a root LaunchDaemon (log monitor) and a user LaunchAgent (notifier) so the user account can run without admin privileges — useful when following least privilege with tools like [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges). The original binary also silently exits 0 when `log stream` fails (stderr wasn't captured), making it hard to diagnose.

`yknotify` watches macOS logs (via `log stream` CLI command) for events that are heuristically associated with the YubiKey waiting for touch. Tested with FIDO2 and OpenPGP features; other applications listed in `ykman info` (e.g., Yubico OTP, FIDO U2F, OATH, PIV, YubiHSM Auth) have not been tested.

When waiting for FIDO2 touch, we'll see this message logged once (with example hex value):

```
kernel: (IOHIDFamily) IOHIDLibUserClient:0x123456789 startQueue
```

When waiting for OpenPGP touch, we'll see this message logged repeatedly:

```
usbsmartcardreaderd: [com.apple.CryptoTokenKit:ccid] Time extension received
```

As soon as the YubiKey is touched, we'll get a new/different log message in the same category. So the strategy here is to check if either of the above messages are the last one logged in their respective categories, and if so, notify the user to touch the YubiKey.

### Why?

When you've tied your YubiKey to many things (SSH, Git signing, GPG, sudo, etc.), you don't always get terminal output indicating a touch is needed. You might find yourself waiting for a "stuck" Git clone to complete, only to realize minutes later that the YubiKey has been silently flashing the whole time.

We ain't training Pavlovian doggies here. Touching your YubiKey should always be an intentful act, and `yknotify` doesn't change that. It's simply a more noticeable version of the YubiKey's flashing green LED.

### Architecture

This fork splits `yknotify` into two services communicating via a named pipe (FIFO):

```
LaunchDaemon (root)                    LaunchAgent (user)
yknotify -fifo /var/run/…   ──FIFO──▶  yknotify.sh
  └─ log stream (needs root)              └─ terminal-notifier
```

- **Daemon** runs as root, monitors `log stream`, writes touch events to the FIFO
- **Agent** runs as the user, reads events from the FIFO, sends desktop notifications
- If either side restarts, the other reconnects automatically

### Install

```bash
# Clone and build
git clone https://github.com/stuartsaunders/yknotify
cd yknotify
go build -o yknotify .

# Install dependencies
brew install terminal-notifier jq

# Install binary, script, and icon (requires sudo)
sudo cp yknotify /usr/local/bin/yknotify
sudo chmod 755 /usr/local/bin/yknotify
sudo mkdir -p /usr/local/share/yknotify
sudo cp yknotify.sh /usr/local/share/yknotify/yknotify.sh
sudo chmod 755 /usr/local/share/yknotify/yknotify.sh
sudo cp yubikey.png /usr/local/share/yknotify/yubikey.png

# Install custom notification sound
mkdir -p ~/Library/Sounds
cp waiting.aiff ~/Library/Sounds/

# Install LaunchDaemon (root log monitor)
sudo cp com.yknotify.daemon.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.yknotify.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.yknotify.daemon.plist

# Install LaunchAgent (user notifier)
cp com.user.yknotify.agent.plist ~/Library/LaunchAgents/

# Start services
sudo launchctl bootstrap system /Library/LaunchDaemons/com.yknotify.daemon.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.user.yknotify.agent.plist
```

### Usage

Run from CLI (no root required for testing, but `log stream` may fail without admin).

```
yknotify
{"ts":"2025-02-12T20:09:03Z","type":"FIDO2"}
{"ts":"2025-02-12T20:09:14Z","type":"OpenPGP"}
```

### Testing

Inject a fake event into the FIFO to verify the notification pipeline end-to-end:

```bash
# Stop the daemon so we can write to the FIFO directly
sudo launchctl bootout system/com.yknotify.daemon

# Send a test event (should trigger a desktop notification)
echo '{"ts":"2026-01-01T00:00:00Z","type":"FIDO2"}' | sudo tee /var/run/yknotify.fifo

# Restart the daemon
sudo launchctl bootstrap system /Library/LaunchDaemons/com.yknotify.daemon.plist
```

Then trigger a real YubiKey operation (SSH, git sign, etc.) to confirm the full path works.

### Verify

```bash
# Check both services are running
sudo launchctl print system/com.yknotify.daemon | grep -E "state|pid"
launchctl print gui/$(id -u)/com.user.yknotify.agent | grep -E "state|pid"

# FIFO exists?
ls -la /var/run/yknotify.fifo

# Check daemon log
sudo cat /var/log/yknotify-daemon.log
```

### Uninstall

```bash
# Stop services
sudo launchctl bootout system/com.yknotify.daemon
launchctl bootout gui/$(id -u)/com.user.yknotify.agent

# Remove files
sudo rm /Library/LaunchDaemons/com.yknotify.daemon.plist
rm ~/Library/LaunchAgents/com.user.yknotify.agent.plist
sudo rm -rf /usr/local/bin/yknotify /usr/local/share/yknotify
sudo rm -f /var/run/yknotify.fifo
```

### Troubleshooting

I've seen a few rare false positives (i.e., a log when the YubiKey is not waiting for touch) that I haven't diagnosed—but _no_ false negatives (i.e., no log when the YubiKey is waiting for touch). If you see false anythings, please open an issue with the log message and I'll try to add a filter for it.

### See also

- https://github.com/maximbaz/yubikey-touch-detector/issues/5#issuecomment-2568300068
- https://news.ycombinator.com/item?id=43029385

### To-do

- [ ] perhaps add a debug flag to show context around related log messages
- [x] add LaunchAgent example
- [x] show how to notify with osascript
