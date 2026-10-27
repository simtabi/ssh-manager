package cli

import (
	"errors"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
)

// recordedFlags are the string flags whose values are names from the manifest
// or settings that carry no secret, so the history keeps them. Every other
// string value is recorded as "<set>": a path, an identity file or an output
// location is the person's business, and an allowlist cannot leak a flag added
// later the way a denylist would.
var recordedFlags = map[string]string{
	"profile":    history.KindProfile,
	"host":       history.KindHost,
	"key-name":   history.KindKey,
	"category":   "",
	"user":       "",
	"hostname":   "",
	"tag":        "",
	"untag":      "",
	"provider":   "",
	"type":       "",
	"proxy":      "",
	"key-scope":  "",
	"vm":         "",
	"mode":       "",
	"hypervisor": "",
	"skip":       "",
	"token-env":  "", // the variable's name, never its value
}

// positional names what each mutating command's arguments are, for the
// history's --host, --profile and --key filters. A "[profile/]key" argument is
// split into both. Commands not listed contribute their events' subjects only.
var positional = map[string][]string{
	"profile add":       {history.KindProfile},
	"profile edit":      {history.KindProfile},
	"profile delete":    {history.KindProfile},
	"host add":          {history.KindProfile, history.KindHost},
	"host edit":         {history.KindProfile, history.KindHost},
	"host delete":       {history.KindProfile, history.KindHost},
	"host apply":        {history.KindProfile, history.KindHost},
	"key add":           {history.KindProfile, history.KindKey},
	"key delete":        {history.KindKey},
	"deploy":            {history.KindKey, history.KindTarget},
	"rollback":          {history.KindKey},
	"rotate":            {history.KindKey},
	"recover":           {history.KindKey},
	"knownhosts pin":    {history.KindHost},
	"vm docker-context": {history.KindHost},
	"load":              {history.KindProfile},
	"init":              {history.KindProfile},
}

func positionalSubjects(command string, args []string) []history.Subject {
	var out []history.Subject
	for i, kind := range positional[command] {
		if i >= len(args) || args[i] == "" {
			break
		}
		a := args[i]
		if kind == history.KindKey {
			if prof, key, ok := strings.Cut(a, "/"); ok {
				out = append(out, history.Subject{Kind: history.KindProfile, Name: prof})
				a = key
			}
		}
		out = append(out, history.Subject{Kind: kind, Name: a})
	}
	return out
}

// recordCommands wraps every command's RunE in a history scope. The scope
// records nothing unless the command mutates - the guard opens the operation
// when the command takes the lock - so read-only commands pass through.
//
// The TUI is a scope of its own, and each action chosen from its menu opens a
// scope inside it, so a session of five changes is five operations.
func recordCommands(root *cobra.Command) {
	mutation.InstallSink()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if run := c.RunE; run != nil {
			c.RunE = func(c *cobra.Command, args []string) error {
				mutation.Begin(scopeFor(c, args))
				err := run(c, args)
				mutation.End(mutation.Outcome{Err: err, Aborted: errors.Is(err, errAborted)})
				return err
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

func scopeFor(c *cobra.Command, args []string) mutation.Scope {
	name := strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), c.Root().Name()))
	source := history.SourceCLI
	if name == "" || name == "tui" {
		name, source = "tui", history.SourceTUI
	}
	s := mutation.Scope{Command: name, Source: source, Args: append([]string{}, args...),
		Subjects: positionalSubjects(name, args)}
	c.Flags().Visit(func(f *pflag.Flag) {
		if f.Name == devRootFlag {
			return
		}
		if f.Name == "dry-run" && f.Value.String() == "true" {
			s.DryRun = true
		}
		s.Args = append(s.Args, "--"+f.Name+"="+recordedValue(f))
		if kind := recordedFlags[f.Name]; kind != "" && f.Value.String() != "" {
			s.Subjects = append(s.Subjects, history.Subject{Kind: kind, Name: f.Value.String()})
		}
	})
	return s
}

func recordedValue(f *pflag.Flag) string {
	switch f.Value.Type() {
	case "bool", "int", "int64", "uint", "duration", "count":
		return f.Value.String()
	}
	if _, ok := recordedFlags[f.Name]; ok {
		return f.Value.String()
	}
	return "<set>"
}
