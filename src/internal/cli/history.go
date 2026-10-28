package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/lock"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

func newHistoryCmd() *cobra.Command {
	var f history.Filter
	var since, until string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List the changes sshmgr has made, newest first",
		Long: "List the operations that changed something - every command that took the lock -\n" +
			"newest first, with how each ended and what it was about.\n\n" +
			"The first run imports what was already on disk: audit.log, the dates inventory.json\n" +
			"records, and the snapshots. Those show as source \"backfill\".\n\n" +
			"--since and --until take a date (2026-10-27), a time (2026-10-27T14:00:00Z) or an\n" +
			"age (36h, 7d).",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			if f.Since, err = parseWhen(since); err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			if f.Until, err = parseWhen(until); err != nil {
				return fmt.Errorf("--until: %w", err)
			}
			s, err := openHistory(c, p)
			if err != nil {
				return err
			}
			defer func() { _ = s.Close() }()
			ops, err := s.Query(f)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				for _, o := range ops {
					if err := enc.Encode(o); err != nil {
						return err
					}
				}
				return nil
			}
			writeHistory(out, ops)
			reportGap(c.ErrOrStderr(), s, p)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.Host, "host", "", "only operations about this host alias")
	fl.StringVar(&f.Profile, "profile", "", "only operations about this profile")
	fl.StringVar(&f.Key, "key", "", "only operations about this key")
	fl.StringVar(&since, "since", "", "only operations started at or after this")
	fl.StringVar(&until, "until", "", "only operations started at or before this")
	fl.StringVar(&f.Command, "command", "", `only this command ("host add"), or a group of them ("host")`)
	fl.StringVar(&f.Source, "source", "", "only operations from cli, tui, web or backfill")
	fl.IntVar(&f.Limit, "limit", 50, "at most this many operations (0 for all)")
	fl.BoolVar(&asJSON, "json", false, "one JSON object per operation, its events nested")

	cmd.AddCommand(&cobra.Command{
		Use:   "show <op_id>",
		Short: "Show one operation: its events and what it changed in the manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			s, err := openHistory(c, p)
			if err != nil {
				return err
			}
			defer func() { _ = s.Close() }()
			op, ok, err := s.Get(args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no operation %q in the history (sshmgr history lists them)", args[0])
			}
			return writeOp(c.OutOrStdout(), s, op)
		},
	})
	return cmd
}

// openHistory opens the store for reading, importing what was on disk the
// first time. The import writes, so it takes the lock for as long as it runs;
// listing afterwards does not.
func openHistory(c *cobra.Command, p paths.Paths) (*history.Store, error) {
	s, err := history.Open(p.HistoryDB())
	if errors.Is(err, history.ErrNewerSchema) {
		_, _ = fmt.Fprintln(c.ErrOrStderr(), "sshmgr: note:", err)
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !s.NeedsBackfill() {
		return s, nil
	}
	release, lerr := lock.Acquire(p.LockFile())
	if lerr == nil {
		defer release()
	}
	if s.NeedsBackfill() { // a command that held the lock may have done it meanwhile
		res, err := s.Backfill(mutation.SourcesFor(p))
		if err != nil {
			return s, fmt.Errorf("importing the earlier history: %w", err)
		}
		if res.Events > 0 {
			_, _ = fmt.Fprintln(c.ErrOrStderr(), res.String())
		}
	}
	return s, nil
}

func writeHistory(out io.Writer, ops []history.Op) {
	if len(ops) == 0 {
		_, _ = fmt.Fprintln(out, "no operations recorded yet")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STARTED\tRESULT\tSOURCE\tCOMMAND\tABOUT\tOP")
	for _, o := range ops {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", o.StartedAt, dash(o.Result), o.Source,
			o.Command, dash(subjectList(o.Subjects)), o.OpID[:8])
	}
	_ = tw.Flush()
}

func writeOp(out io.Writer, s *history.Store, o history.Op) error {
	row := func(k, v string) {
		if v != "" {
			_, _ = fmt.Fprintf(out, "%-10s %s\n", k, v)
		}
	}
	row("op", o.OpID)
	row("command", strings.TrimSpace(o.Command+" "+strings.Join(o.Args, " ")))
	row("source", o.Source)
	row("started", o.StartedAt)
	row("finished", o.FinishedAt)
	row("result", o.Result)
	row("error", o.Error)
	row("about", subjectList(o.Subjects))
	row("snapshot", o.Snapshot)
	row("by", strings.Trim(o.OSUser+"@"+o.Machine, "@"))
	row("version", o.Version)
	if len(o.Events) > 0 {
		_, _ = fmt.Fprintln(out, "\nevents")
		for _, e := range o.Events {
			_, _ = fmt.Fprintf(out, "  %s  %s  %s\n", e.TS, e.Event, e.Fields)
		}
	}
	_, _ = fmt.Fprintln(out)
	switch {
	case o.ManifestBefore == "" || o.ManifestAfter == "":
		_, _ = fmt.Fprintln(out, "no manifest recorded for this operation")
	case o.ManifestBefore == o.ManifestAfter:
		_, _ = fmt.Fprintln(out, "the manifest did not change")
	default:
		before, err := s.Manifest(o.ManifestBefore)
		if err != nil {
			return err
		}
		after, err := s.Manifest(o.ManifestAfter)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "--- manifest before (%s)\n+++ manifest after (%s)\n", o.ManifestBefore[:12], o.ManifestAfter[:12])
		_, _ = io.WriteString(out, history.FormatDiff(history.Diff(string(before), string(after), 3)))
	}
	return nil
}

// reportGap says when audit.log holds events the store does not: a write to
// the store that failed leaves the event in audit.log only, and the history
// should not quietly read as complete.
func reportGap(errw io.Writer, s *history.Store, p paths.Paths) {
	since := s.Meta(history.MetaBackfillDone)
	if since == "" {
		return
	}
	audit := 0
	for _, f := range []string{p.AuditLog() + ".1", p.AuditLog()} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if a, ok := history.ParseAuditLine([]byte(line)); ok && a.TS > since {
				audit++
			}
		}
	}
	stored := s.LiveAuditEvents(since)
	if audit > stored {
		_, _ = fmt.Fprintf(errw, "note: audit.log has %d event(s) since %s that the history does not\n", audit-stored, since)
	}
}

func subjectList(subs []history.Subject) string {
	var parts []string
	for _, s := range subs {
		parts = append(parts, s.Kind+":"+s.Name)
	}
	return strings.Join(parts, " ")
}

// parseWhen reads a --since/--until bound: a date, a time, or an age counted
// back from now ("36h", "7d").
func parseWhen(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.HasSuffix(s, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil && n >= 0 {
			return time.Now().UTC().AddDate(0, 0, -n).Format(history.TimeFormat), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return time.Now().UTC().Add(-d).Format(history.TimeFormat), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(history.TimeFormat), nil
	}
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return s, nil
	}
	return "", fmt.Errorf("%q is not a date, a time or an age like 7d", s)
}
