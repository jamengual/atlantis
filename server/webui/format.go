// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// tone is the status color family used by pills and markers.
type tone string

const (
	toneOK      tone = "ok"
	toneWarn    tone = "warn"
	toneBad     tone = "bad"
	toneRun     tone = "run"
	toneNeutral tone = ""
)

type stateInfo struct {
	Tone  tone
	Label string
}

func describeState(s ProjectState) stateInfo {
	switch s {
	case StateRunning:
		return stateInfo{toneRun, "Running"}
	case StatePlanned:
		return stateInfo{toneNeutral, "Planned"}
	case StateNoChanges:
		return stateInfo{toneOK, "No changes"}
	case StateApplied:
		return stateInfo{toneOK, "Applied"}
	case StatePlanFailed:
		return stateInfo{toneBad, "Plan failed"}
	case StateApplyFailed:
		return stateInfo{toneBad, "Apply failed"}
	case StateDiscarded:
		return stateInfo{toneNeutral, "Discarded"}
	case StatePolicyFailed:
		return stateInfo{toneWarn, "Policy failed"}
	case StatePolicyPassed:
		return stateInfo{toneOK, "Policies passed"}
	}
	return stateInfo{toneNeutral, string(s)}
}

// pullState summarizes a pull request by its most urgent project state.
func pullState(p PullRequest) ProjectState {
	order := []ProjectState{StateRunning, StatePlanFailed, StateApplyFailed, StatePolicyFailed, StatePlanned, StatePolicyPassed, StateNoChanges, StateApplied, StateDiscarded}
	for _, want := range order {
		for _, proj := range p.Projects {
			if proj.State == want {
				return want
			}
		}
	}
	return StateDiscarded
}

// pullFilters are the filter chips on the pull request list.
var pullFilters = []struct{ Key, Label string }{
	{"", "All"},
	{"running", "Running"},
	{"apply", "Needs apply"},
	{"failed", "Failed"},
	{"policy", "Needs policy approval"},
}

func matchesFilter(p PullRequest, filter string) bool {
	st := pullState(p)
	switch filter {
	case "running":
		return st == StateRunning
	case "apply":
		return st == StatePlanned || st == StatePolicyPassed
	case "failed":
		return st == StatePlanFailed || st == StateApplyFailed
	case "policy":
		return st == StatePolicyFailed
	}
	return true
}

// ago formats the time between t and now in the largest useful unit.
func ago(now, t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// held formats how long something has been held, without "ago".
func held(now, t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func itoa(n int) string { return strconv.Itoa(n) }

// staleAfter is how long a lock can be held before the UI flags it.
const staleAfter = 7 * 24 * time.Hour

func lockStale(now time.Time, l Lock) bool {
	return !l.PullTracked || now.Sub(l.Since) > staleAfter
}

// attentionItem is one row in the overview's "Needs attention" list.
type attentionItem struct {
	Tone   tone
	Title  string
	Detail string
	Href   string
	Action string
}

// needsAttention picks the pull requests and locks an operator should look at,
// most urgent first.
func needsAttention(now time.Time, pulls []PullRequest, locks []Lock, base string) []attentionItem {
	var bad, warn, info []attentionItem
	for _, p := range pulls {
		href := pullHref(base, p.Repo, p.Num)
		name := fmt.Sprintf("%s #%d", p.Repo.FullName, p.Num)
		for _, proj := range p.Projects {
			switch proj.State {
			case StatePlanFailed, StateApplyFailed:
				bad = append(bad, attentionItem{toneBad, fmt.Sprintf("%s: %s in %s", name, lowerFirst(describeState(proj.State).Label), projectLabel(proj)), "Open the log to see the error.", href, "View"})
			case StatePolicyFailed:
				warn = append(warn, attentionItem{toneWarn, fmt.Sprintf("%s is waiting for a policy approval in %s", name, projectLabel(proj)), "Approve the policies or update the code, then plan again.", href, "Review"})
			}
		}
	}
	for _, l := range locks {
		switch {
		case !l.PullTracked:
			warn = append(warn, attentionItem{toneWarn, fmt.Sprintf("Lock on %s is held by pull request #%d, which Atlantis no longer tracks", lockLabel(l), l.PullNum), fmt.Sprintf("Held for %s by %s. Other pull requests can't plan this project until it's unlocked.", held(now, l.Since), orUnknown(l.User)), base + "/ui/locks", "Open locks"})
		case now.Sub(l.Since) > staleAfter:
			info = append(info, attentionItem{toneRun, fmt.Sprintf("Lock on %s has been held for %s", lockLabel(l), held(now, l.Since)), fmt.Sprintf("Pull request #%d by %s.", l.PullNum, orUnknown(l.PullAuthor)), base + "/ui/locks", "Open locks"})
		}
	}
	return append(append(bad, warn...), info...)
}

func projectLabel(p Project) string {
	label := p.Dir
	if p.Name != "" {
		label = p.Name
	}
	if p.Workspace != "" && p.Workspace != "default" {
		label += " (" + p.Workspace + ")"
	}
	return label
}

func lockLabel(l Lock) string {
	label := l.Dir
	if l.ProjectName != "" {
		label = l.ProjectName
	}
	return label
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'A' && b[0] <= 'Z' {
		b[0] += 'a' - 'A'
	}
	return string(b)
}

// pullHref links to a pull request page. The host is included so repositories
// with the same name on different VCS hosts stay distinct.
func pullHref(base string, repo Repository, num int) string {
	parts := strings.Split(repo.FullName, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	href := fmt.Sprintf("%s/ui/repos/%s/pulls/%d", base, strings.Join(parts, "/"), num)
	if repo.VCSHost != "" {
		href += "?host=" + url.QueryEscape(repo.VCSHost)
	}
	return href
}

func jobHref(base, id string) string {
	return base + "/ui/jobs/" + url.PathEscape(id)
}

// ledgerWidths splits a bar of width w between additions, changes and
// destroys. Imports and forgets count as changes for the bar.
func ledgerWidths(c Changes, w int) (add, change, destroy int) {
	total := c.Total()
	if total == 0 {
		return 0, 0, 0
	}
	add = c.Add * w / total
	destroy = c.Destroy * w / total
	change = w - add - destroy
	return add, change, destroy
}

func initials(name string) string {
	if name == "" {
		return "?"
	}
	fields := strings.FieldsFunc(name, func(r rune) bool { return r == ' ' || r == '.' || r == '-' || r == '_' || r == '@' })
	out := ""
	for _, f := range fields {
		if len(out) == 2 {
			break
		}
		out += strings.ToUpper(f[:1])
	}
	return out
}

func firstN[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func filterQuery(key string) string {
	if key == "" {
		return ""
	}
	return "?state=" + url.QueryEscape(key)
}

func countStale(now time.Time, locks []Lock) int {
	n := 0
	for _, l := range locks {
		if lockStale(now, l) {
			n++
		}
	}
	return n
}

func jobLabel(j Job) string {
	label := j.Dir
	if j.ProjectName != "" {
		label = j.ProjectName
	}
	if label == "" {
		label = j.Description
	}
	if label == "" {
		label = j.ID
	}
	if j.Workspace != "" && j.Workspace != "default" {
		label += " (" + j.Workspace + ")"
	}
	return label
}

func joinOr(items []string, empty string) string {
	if len(items) == 0 {
		return empty
	}
	return strings.Join(items, ", ")
}

func capText(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
