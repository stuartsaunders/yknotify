package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPredicate = `(processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily") OR (subsystem CONTAINS "CryptoTokenKit")`

	// FIDO2 CTAP2 user presence timeout — real touch waits end within this
	// window (either by touch, stopQueue from the client, or device timeout).
	// Pending startQueues older than this are pruned as stuck state.
	fido2Timeout = 30 * time.Second

	// Grace period before a sustained startQueue is treated as a real touch
	// wait. Legitimate enumeration / probe opens (plug-in, Yubico Authenticator
	// reading device info) resolve in milliseconds with a matching stopQueue;
	// real CTAP2 user-presence waits hold the queue open for seconds to tens
	// of seconds. 1500ms is comfortably above probe duration and well below
	// real touch latency.
	fido2GracePeriod = 1500 * time.Millisecond

	// Re-notify interval while a touch remains pending. The YubiKey LED blinks
	// throughout but users often miss a single toast — a repeat every few
	// seconds helps catch it. Capped implicitly by fido2Timeout and by the
	// underlying operation's own CTAP2 timeout.
	renotifyInterval = 5 * time.Second
)

var (
	predicate = flag.String("predicate", defaultPredicate, "NSPredicate filter for log stream")
	noFilter  = flag.Bool("no-filter", false, "Disable log filtering (warning: high CPU usage)")
	fifoPath  = flag.String("fifo", "", "Write output to a named pipe (FIFO) instead of stdout")
)

type LogEntry struct {
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	Subsystem        string `json:"subsystem"`
	EventMessage     string `json:"eventMessage"`
}

type TouchState struct {
	mu sync.Mutex
	// Pending startQueue events keyed by IOHIDLibUserClient id. An entry is
	// promoted to a FIDO2 touch notification only after fido2GracePeriod has
	// elapsed without a matching stopQueue. This filters brief open+probe
	// cycles from enumeration and device-info reads.
	fido2Pending map[string]time.Time
	// Last notification timestamps per type. Zero value means never notified
	// for the current pending cycle; reset when the state transitions back
	// to not-needed. Used to drive both the initial fire (on false→true) and
	// re-fires every renotifyInterval while still pending.
	fido2LastNotify   time.Time
	openPGPNeeded     bool
	openPGPLastNotify time.Time
	output            io.Writer
	writeErr          error
}

type TouchEvent struct {
	Timestamp string `json:"ts"`
	Type      string `json:"type"`
}

// checkAndNotify recomputes pending state and fires a notification on the
// false→true transition, then re-fires every renotifyInterval while the
// touch remains pending. Repeats stop as soon as the pending state clears
// (stopQueue from the client, or the CTAP2 timeout prune).
func (ts *TouchState) checkAndNotify() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.writeErr != nil {
		return
	}

	now := time.Now()

	// Prune pending entries older than CTAP2 timeout. A stuck entry without a
	// matching stopQueue (e.g. process crashed holding the queue open) would
	// otherwise keep re-firing long past any possible real touch.
	for id, t := range ts.fido2Pending {
		if now.Sub(t) > fido2Timeout {
			delete(ts.fido2Pending, id)
		}
	}

	// A pending entry older than fido2GracePeriod is a real touch wait.
	fido2Needed := false
	for _, t := range ts.fido2Pending {
		if now.Sub(t) >= fido2GracePeriod {
			fido2Needed = true
			break
		}
	}

	// Reset re-notify timer when state transitions back to not-needed, so the
	// next pending cycle fires immediately rather than waiting out the interval.
	if !fido2Needed {
		ts.fido2LastNotify = time.Time{}
	}
	if !ts.openPGPNeeded {
		ts.openPGPLastNotify = time.Time{}
	}

	if fido2Needed && (ts.fido2LastNotify.IsZero() || now.Sub(ts.fido2LastNotify) >= renotifyInterval) {
		log.Printf("notifying FIDO2 (pending=%d)", len(ts.fido2Pending))
		if err := ts.writeEvent(now, "FIDO2"); err != nil {
			return
		}
		ts.fido2LastNotify = now
	}
	if ts.openPGPNeeded && (ts.openPGPLastNotify.IsZero() || now.Sub(ts.openPGPLastNotify) >= renotifyInterval) {
		if err := ts.writeEvent(now, "OpenPGP"); err != nil {
			return
		}
		ts.openPGPLastNotify = now
	}
}

// writeEvent marshals and writes a TouchEvent. Caller must hold ts.mu.
// On write failure the error is stored on the state so the scanner loop can
// unwind cleanly (typically: reader disconnected from the FIFO).
func (ts *TouchState) writeEvent(now time.Time, kind string) error {
	event := TouchEvent{
		Type:      kind,
		Timestamp: now.UTC().Format(time.RFC3339),
	}
	bytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(ts.output, string(bytes)); err != nil {
		ts.writeErr = err
		return err
	}
	return nil
}

// isYubiKeyFIDO2Device checks whether an IORegistry device ID belongs to a
// Yubico FIDO2 HID interface. It requires both:
//   - "Manufacturer" = "Yubico" (rules out non-YubiKey USB HID devices)
//   - "PrimaryUsagePage" = 61904 (0xF1D0, FIDO Alliance usage page)
//
// The second check is critical: a YubiKey exposes multiple HID interfaces
// (keyboard/OTP on usage page 1, FIDO2 on usage page 0xF1D0). Input managers
// like BetterTouchTool open the keyboard interface and call startQueue as part
// of normal HID setup — tracking those clients would cause false positives.
func isYubiKeyFIDO2Device(deviceID string) bool {
	out, err := exec.Command("ioreg", "-r", "-l", "-c", "AppleUserUSBHostHIDDevice").Output()
	if err != nil {
		log.Printf("ioreg lookup failed: %v", err)
		return false
	}

	// Parse ioreg output. Device blocks start with "+-o AppleUserUSBHostHIDDevice"
	// lines containing "id 0x<hex>". We match on the device's registry ID and
	// check for both "Manufacturer" = "Yubico" and "PrimaryUsagePage" = 61904
	// within that block.
	const fido2UsagePage = 61904 // 0xF1D0 — FIDO Alliance
	lines := strings.Split(string(out), "\n")
	inTargetDevice := false
	isYubico := false
	isFIDO2 := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// New device block — match "id <deviceID>" in the header.
		// e.g., +-o AppleUserUSBHostHIDDevice  <class ..., id 0x10002e356, ...>
		if strings.HasPrefix(trimmed, "+-o ") {
			if inTargetDevice {
				// We've exited the target block without finding both conditions.
				break
			}
			inTargetDevice = strings.Contains(trimmed, "id "+deviceID+",")
			continue
		}

		if !inTargetDevice {
			continue
		}

		if strings.Contains(trimmed, "\"Manufacturer\"") {
			isYubico = strings.Contains(trimmed, "\"Yubico\"")
		}
		if strings.Contains(trimmed, "\"PrimaryUsagePage\"") {
			isFIDO2 = strings.Contains(trimmed, fmt.Sprintf("= %d", fido2UsagePage))
		}
		if isYubico && isFIDO2 {
			return true
		}
	}

	return false
}

// hidClientCreator returns the IOUserClientCreator string for a given
// IOHIDLibUserClient registry id, or "" if the entry cannot be found.
//
// The creator string looks like: "pid 12345, Yubico Authenticator" — it's
// the creating process's argv[0] as seen by IOKit when the user client was
// instantiated. We use it for process-aware suppression without needing to
// invoke `ps` or `lsof`.
func hidClientCreator(clientID string) string {
	// Kernel log uses "IOHIDLibUserClient:0x..." as the clientID; ioreg prints
	// "id 0x..." without the class prefix. Strip to the bare hex id.
	bareID := clientID
	if i := strings.LastIndex(bareID, ":"); i >= 0 {
		bareID = bareID[i+1:]
	}
	out, err := exec.Command("ioreg", "-c", "IOHIDLibUserClient", "-l", "-r", "-w", "0").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	inTarget := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "+-o ") {
			if inTarget {
				// Exited the target block without finding the property.
				break
			}
			inTarget = strings.Contains(trimmed, "id "+bareID+",")
			continue
		}
		if inTarget && strings.Contains(trimmed, "\"IOUserClientCreator\"") {
			// e.g.  "IOUserClientCreator" = "pid 12345, <argv0>"
			if eq := strings.Index(trimmed, "= "); eq >= 0 {
				return strings.Trim(trimmed[eq+2:], "\"")
			}
		}
	}
	return ""
}

// touchlessFIDO2Apps lists argv[0] substrings of processes that open the
// FIDO2 HID interface for non-touch reasons (device info, client-PIN entry,
// credential enumeration). Yubico Authenticator's "Accounts" and "Passkeys"
// tabs send CTAP2 clientPIN commands and hold startQueue open for the
// duration of the PIN prompt — which from the log signal alone is
// indistinguishable from a real user-presence wait.
var touchlessFIDO2Apps = []string{
	"yubico authenticator",
	"authenticator-he", // Yubico Authenticator helper (ioreg truncates the binary name)
	"ykman",
}

// isTouchlessFIDO2Client matches the IOUserClientCreator string against
// known touchless apps. Case-insensitive substring match.
func isTouchlessFIDO2Client(creator string) bool {
	if creator == "" {
		return false
	}
	lower := strings.ToLower(creator)
	for _, app := range touchlessFIDO2Apps {
		if strings.Contains(lower, app) {
			return true
		}
	}
	return false
}

// openFifo creates the FIFO if it doesn't exist and opens it for writing.
// The open blocks until a reader connects — this is intentional.
func openFifo(path string) (*os.File, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := syscall.Mkfifo(path, 0644); err != nil {
			return nil, fmt.Errorf("mkfifo %s: %w", path, err)
		}
	}
	// O_WRONLY blocks until a reader opens the other end
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open fifo %s: %w", path, err)
	}
	return f, nil
}

func streamLogs(output io.Writer) error {
	args := []string{"stream", "--level", "debug", "--style", "ndjson"}
	if !*noFilter {
		args = append(args, "--predicate", *predicate)
	}
	cmd := exec.Command("log", args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	state := &TouchState{
		output:       output,
		fido2Pending: make(map[string]time.Time),
	}
	scanner := bufio.NewScanner(stdout)
	yubiKeyClients := make(map[string]bool)

	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			state.checkAndNotify()
		}
	}()

	for scanner.Scan() {
		// If a write to the FIFO failed, stop processing
		state.mu.Lock()
		writeErr := state.writeErr
		state.mu.Unlock()
		if writeErr != nil {
			_ = cmd.Process.Kill()
			return writeErr
		}

		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		switch {
		case entry.ProcessImagePath == "/kernel" &&
			strings.HasSuffix(entry.SenderImagePath, "IOHIDFamily"):
			msg := entry.EventMessage

			// e.g., AppleUserUSBHostHIDDevice:0x100000c81 open by IOHIDLibUserClient:0x10016f869 (0x1)
			// Only track clients for confirmed YubiKey devices (vendor ID 0x1050).
			if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "open by IOHIDLibUserClient:") {
				// Extract device ID (e.g., "0x100000c81") and client ID
				devicePart := strings.SplitN(msg, " open by ", 2)
				if len(devicePart) == 2 {
					deviceID := strings.TrimPrefix(devicePart[0], "AppleUserUSBHostHIDDevice:")
					clientID := strings.Split(devicePart[1], " ")[0]

					if isYubiKeyFIDO2Device(deviceID) {
						creator := hidClientCreator(clientID)
						if isTouchlessFIDO2Client(creator) {
							log.Printf("ignored touchless FIDO2 client %s (creator %q)", clientID, creator)
						} else {
							yubiKeyClients[clientID] = true
							log.Printf("tracked YubiKey HID client %s (device %s, creator %q)", clientID, deviceID, creator)
						}
					} else {
						log.Printf("ignored non-YubiKey HID device %s", deviceID)
					}
				}
			}

			// e.g., IOHIDLibUserClient:0x10016f869 startQueue
			// Record pending; checkAndNotify promotes to a notification only
			// if fido2GracePeriod elapses without a matching stopQueue.
			if strings.HasSuffix(msg, "startQueue") {
				clientID := strings.Split(msg, " ")[0]
				tracked := yubiKeyClients[clientID]
				log.Printf("startQueue %s tracked=%v", clientID, tracked)
				if tracked {
					state.mu.Lock()
					state.fido2Pending[clientID] = time.Now()
					state.mu.Unlock()
				}
			} else if strings.HasSuffix(msg, "stopQueue") {
				clientID := strings.Split(msg, " ")[0]
				tracked := yubiKeyClients[clientID]
				if tracked {
					state.mu.Lock()
					age := time.Duration(0)
					if t, ok := state.fido2Pending[clientID]; ok {
						age = time.Since(t)
					}
					delete(state.fido2Pending, clientID)
					state.mu.Unlock()
					log.Printf("stopQueue %s tracked=true pending_age=%v", clientID, age)
				}
			}

		case strings.HasSuffix(entry.ProcessImagePath, "usbsmartcardreaderd") &&
			strings.HasSuffix(entry.Subsystem, "CryptoTokenKit"):
			state.mu.Lock()
			state.openPGPNeeded = entry.EventMessage == "Time extension received"
			state.mu.Unlock()
		}
		state.checkAndNotify()
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.writeErr
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	if *fifoPath == "" {
		// No FIFO — original behavior, write to stdout
		if err := streamLogs(os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Ignore SIGPIPE so we can detect write failures and reconnect
	signal.Ignore(syscall.SIGPIPE)

	// Reconnection loop: re-open FIFO when the reader disconnects
	for {
		log.Printf("opening fifo %s (waiting for reader)", *fifoPath)
		f, err := openFifo(*fifoPath)
		if err != nil {
			log.Printf("fifo open error: %v; retrying in 1s", err)
			time.Sleep(time.Second)
			continue
		}

		log.Printf("reader connected, streaming logs")
		err = streamLogs(f)
		f.Close()

		if err != nil {
			log.Printf("stream error: %v; reconnecting", err)
		} else {
			log.Printf("stream ended; reconnecting")
		}
	}
}
