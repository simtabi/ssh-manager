// Package log writes the append-only audit trail, ported from util/log.audit.
// Each event is one JSON line: {ts, event, ...fields}. The log lives in the config
// home (not ~/.ssh), so it is outside the reconcile/render parity surface.
package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Field is one ordered key/value pair in an audit record. Order is preserved in
// the emitted JSON (the order v1 emitted them in).
type Field struct {
	Key   string
	Value any
}

// Retention for the audit trail. The log records every hostname, profile and key
// the user has ever touched, so it is a privacy artifact as much as an
// operational one and cannot grow without bound. Past the size cap the live file
// is rotated to .1 and the previous .1 is dropped, so at most two generations
// exist.
const (
	maxAuditBytes = 2 << 20
	rotatedSuffix = ".1"
)

// Audit appends one JSON line to auditLog (best-effort: I/O errors are
// swallowed). The parent dir is created 0700 and a freshly created log is 0600.
func Audit(auditLog, event string, fields ...Field) {
	var b strings.Builder
	b.WriteByte('{')
	writeKV(&b, "ts", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	b.WriteByte(',')
	writeKV(&b, "event", event)
	for _, f := range fields {
		b.WriteByte(',')
		writeKV(&b, f.Key, f.Value)
	}
	b.WriteString("}\n")

	dir := filepath.Dir(auditLog)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.Chmod(dir, 0o700)
	rotateIfLarge(auditLog)
	_, statErr := os.Stat(auditLog)
	isNew := os.IsNotExist(statErr)
	f, err := os.OpenFile(auditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(b.String())
	if isNew {
		_ = os.Chmod(auditLog, 0o600)
	}
}

// rotateIfLarge moves an oversized log aside, discarding the older generation.
func rotateIfLarge(auditLog string) {
	fi, err := os.Stat(auditLog)
	if err != nil || fi.Size() < maxAuditBytes {
		return
	}
	rotated := auditLog + rotatedSuffix
	_ = os.Remove(rotated)
	if os.Rename(auditLog, rotated) == nil {
		_ = os.Chmod(rotated, 0o600)
	}
}

func writeKV(b *strings.Builder, key string, value any) {
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(value)
	b.Write(kb)
	b.WriteByte(':')
	b.Write(vb)
}
