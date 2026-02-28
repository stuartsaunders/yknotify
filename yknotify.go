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

	// FIDO2 CTAP2 user presence timeout
	fido2Timeout = 30 * time.Second
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
	mu            sync.Mutex
	fido2Needed   bool
	fido2Since    time.Time
	openPGPNeeded bool
	lastNotify    time.Time
	output        io.Writer
	writeErr      error
}

type TouchEvent struct {
	Timestamp string `json:"ts"`
	Type      string `json:"type"`
}

func (ts *TouchState) checkAndNotify() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.writeErr != nil {
		return
	}

	now := time.Now()

	// Auto-clear stale FIDO2 state (CTAP2 times out after 30s)
	if ts.fido2Needed && now.Sub(ts.fido2Since) > fido2Timeout {
		ts.fido2Needed = false
	}

	if now.Sub(ts.lastNotify) < 5*time.Second {
		return
	}

	if ts.fido2Needed {
		event := TouchEvent{
			Type:      "FIDO2",
			Timestamp: now.UTC().Format(time.RFC3339),
		}
		if bytes, err := json.Marshal(event); err == nil {
			if _, err := fmt.Fprintln(ts.output, string(bytes)); err != nil {
				ts.writeErr = err
				return
			}
		}
	}
	if ts.openPGPNeeded {
		event := TouchEvent{
			Type:      "OpenPGP",
			Timestamp: now.UTC().Format(time.RFC3339),
		}
		if bytes, err := json.Marshal(event); err == nil {
			if _, err := fmt.Fprintln(ts.output, string(bytes)); err != nil {
				ts.writeErr = err
				return
			}
		}
	}
	ts.lastNotify = now
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

	state := &TouchState{output: output}
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
						yubiKeyClients[clientID] = true
						log.Printf("tracked YubiKey HID client %s (device %s)", clientID, deviceID)
					} else {
						log.Printf("ignored non-YubiKey HID device %s", deviceID)
					}
				}
			}

			// e.g., IOHIDLibUserClient:0x10016f869 startQueue
			// Only trigger FIDO2 for tracked YubiKey clients.
			if strings.HasSuffix(msg, "startQueue") {
				clientID := strings.Split(msg, " ")[0]
				if yubiKeyClients[clientID] {
					state.mu.Lock()
					state.fido2Needed = true
					state.fido2Since = time.Now()
					state.mu.Unlock()
				}
			} else if strings.HasSuffix(msg, "stopQueue") {
				clientID := strings.Split(msg, " ")[0]
				if yubiKeyClients[clientID] {
					state.mu.Lock()
					state.fido2Needed = false
					state.mu.Unlock()
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
