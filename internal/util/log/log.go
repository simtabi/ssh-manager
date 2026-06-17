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
// the emitted JSON (matching Python's dict insertion order).
type Field struct {
	Key   string
	Value any
}

// Audit appends one JSON line to auditLog (best-effort: I/O errors are swallowed,
// as in v1). The parent dir is created 0700 and a freshly created log is 0600.
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
	_, statErr := os.Stat(auditLog)
	isNew := os.IsNotExist(statErr)
	f, err := os.OpenFile(auditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(b.String())
	if isNew {
		_ = os.Chmod(auditLog, 0o600)
	}
}

func writeKV(b *strings.Builder, key string, value any) {
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(value)
	b.Write(kb)
	b.WriteByte(':')
	b.Write(vb)
}
