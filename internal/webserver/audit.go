package webserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/astoreyai/hostdesk/internal/model"
)

const auditLimit = 1000

type auditLog struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	entries []model.AuditEntry
	next    int
	lines   int
	failed  bool
}

func openAudit(dir string) (*auditLog, error) {
	path := filepath.Join(dir, "audit.jsonl")
	file, err := openPrivate(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_APPEND)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Size() > 16<<20 {
		file.Close()
		return nil, errors.New("local audit exceeds the supported size")
	}
	log := &auditLog{file: file, path: path, entries: make([]model.AuditEntry, 0, auditLimit)}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		var entry model.AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			file.Close()
			return nil, errors.New("local audit contains an incomplete or invalid record; preserve it before recovery")
		}
		log.remember(entry)
		log.lines++
	}
	if err := scanner.Err(); err != nil {
		file.Close()
		return nil, err
	}
	// An unterminated JSON value can be complete yet must not be concatenated
	// with the next event after a crash.
	if info.Size() > 0 {
		var last [1]byte
		if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
			file.Close()
			return nil, err
		}
		if last[0] != '\n' {
			if _, err := file.Write([]byte{'\n'}); err != nil {
				file.Close()
				return nil, err
			}
			if err := file.Sync(); err != nil {
				file.Close()
				return nil, err
			}
		}
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		file.Close()
		return nil, err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		file.Close()
		return nil, err
	}
	return log, nil
}

func (a *auditLog) remember(entry model.AuditEntry) {
	if len(a.entries) < auditLimit {
		a.entries = append(a.entries, entry)
		return
	}
	a.entries[a.next] = entry
	a.next = (a.next + 1) % auditLimit
}

func (a *auditLog) ordered() []model.AuditEntry {
	result := make([]model.AuditEntry, 0, len(a.entries))
	result = append(result, a.entries[a.next:]...)
	result = append(result, a.entries[:a.next]...)
	return result
}

func (a *auditLog) append(entry model.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return errors.New("local audit persistence is unavailable")
	}
	entry.Time = time.Now().UTC()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if a.lines >= 4*auditLimit {
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		for _, prior := range a.ordered() {
			if err := encoder.Encode(prior); err != nil {
				return err
			}
		}
		if _, err := buffer.Write(data); err != nil {
			return err
		}
		if err := writePrivateBytes(a.path, buffer.Bytes()); err != nil {
			a.failed = true
			return err
		}
		newFile, err := openPrivate(a.path, syscall.O_RDWR|syscall.O_APPEND)
		if err != nil {
			a.failed = true
			return err
		}
		_ = a.file.Close()
		a.file = newFile
		a.lines = len(a.entries) + 1
	} else {
		n, err := a.file.Write(data)
		if err != nil {
			a.failed = true
			return err
		}
		if n != len(data) {
			a.failed = true
			return io.ErrShortWrite
		}
		if err := a.file.Sync(); err != nil {
			a.failed = true
			return err
		}
		a.lines++
	}
	a.remember(entry)
	return nil
}

func (a *auditLog) snapshot() []model.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ordered()
}

func (a *auditLog) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.file.Close()
}

func (s *server) getAudit(w http.ResponseWriter, r *http.Request) {
	entries := s.audit.snapshot()
	warnings := []string{}
	if s.broker != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		remote, err := s.broker.Audit(ctx)
		cancel()
		if err != nil {
			warnings = append(warnings, "The privileged broker audit is unavailable. Only local user actions are shown.")
		} else {
			entries = append(entries, remote...)
		}
	} else {
		warnings = append(warnings, "No privileged broker is configured. Only local user actions are recorded here.")
	}
	s.audit.mu.Lock()
	if s.audit.failed {
		warnings = append(warnings, "Local audit persistence failed. User-service controls are disabled until the storage issue is resolved and the server is restarted.")
	}
	s.audit.mu.Unlock()
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
	if len(entries) > auditLimit {
		entries = entries[:auditLimit]
	}
	writeJSON(w, 200, struct {
		Entries  []model.AuditEntry `json:"entries"`
		Warnings []string           `json:"warnings"`
	}{entries, warnings})
}
