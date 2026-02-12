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
	"syscall"
	"time"
)

const defaultPredicate = `(processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily") OR (subsystem CONTAINS "CryptoTokenKit")`

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
	fido2Needed   bool
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
	if ts.writeErr != nil {
		return
	}

	now := time.Now()
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
		if state.writeErr != nil {
			_ = cmd.Process.Kill()
			return state.writeErr
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
			// Other HID types (e.g., AppleUSBTopCaseHIDDriver) do not correspond to YubiKey and will trigger a false positive.
			if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "open by IOHIDLibUserClient:") {
				parts := strings.Split(msg, " open by ")
				if len(parts) == 2 {
					clientID := strings.Split(parts[1], " ")[0]
					yubiKeyClients[clientID] = true
				}
			}

			// e.g., IOHIDLibUserClient:0x10016f869 startQueue
			// Only trigger FIDO2 for tracked YubiKey clients.
			if strings.HasSuffix(msg, "startQueue") {
				clientID := strings.Split(msg, " ")[0]
				state.fido2Needed = yubiKeyClients[clientID]
			} else if strings.HasSuffix(msg, "stopQueue") {
				clientID := strings.Split(msg, " ")[0]
				if yubiKeyClients[clientID] {
					state.fido2Needed = false
				}
			}

		case strings.HasSuffix(entry.ProcessImagePath, "usbsmartcardreaderd") &&
			strings.HasSuffix(entry.Subsystem, "CryptoTokenKit"):
			state.openPGPNeeded = entry.EventMessage == "Time extension received"
		}
		state.checkAndNotify()
	}

	if err := scanner.Err(); err != nil {
		return err
	}
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
