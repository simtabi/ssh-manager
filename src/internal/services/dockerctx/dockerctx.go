// Package dockerctx creates the Docker context that reaches a VM host over
// SSH: `docker context create <alias> --docker host=ssh://<alias>`, or update
// when one by that name is already there.
package dockerctx

import (
	"fmt"
	"os/exec"
	"strings"
)

// Available reports whether the docker CLI is on PATH.
func Available() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker CLI not found")
	}
	return nil
}

// Verb is what Apply would do for alias: "create", or "update" when a
// context by that name already exists.
func Verb(alias string) string {
	if exec.Command("docker", "context", "inspect", alias).Run() == nil {
		return "update"
	}
	return "create"
}

// Apply creates or updates the context and returns the line to report.
func Apply(alias string) (string, error) {
	endpoint := "host=ssh://" + alias
	verb := Verb(alias)
	out, err := exec.Command("docker", "context", verb, alias, "--docker", endpoint).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker context %s: %v: %s", verb, err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("docker context %s %s -> ssh://%s (use: docker --context %s ps)",
		verb+"d", alias, alias, alias), nil
}
