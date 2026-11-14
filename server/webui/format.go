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
		return st == StatePolicyFailed || p.PolicyFailing()
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
			switch {
			case proj.State == StatePlanFailed || proj.State == StateApplyFailed:
				bad = append(bad, attentionItem{toneBad, fmt.Sprintf("%s: %s in %s", name, lowerFirst(describeState(proj.State).Label), projectLabel(proj)), "Open the log to see the error.", href, "View"})
			case proj.PolicyFailing():
				sets := proj.FailingPolicySets()
				warn = append(warn, attentionItem{toneWarn, fmt.Sprintf("%s is waiting for a policy approval in %s", name, projectLabel(proj)),
					fmt.Sprintf("Failing %s: %s. A policy owner can approve, or update the code and plan again.", plural(len(sets), "policy set", "policy sets"), strings.Join(sets, ", ")),
					policiesHref(base, p.Repo, p.Num, proj.Ref()), "Review"})
			case proj.State == StatePolicyFailed:
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

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func providerMark(id string) string {
	switch id {
	case "github":
		return "GH"
	case "oidc":
		return "ID"
	case "google":
		return "G"
	}
	return "?"
}

// planHref links to a project's plan page.
func planHref(base string, repo Repository, num int, ref ProjectRef) string {
	href, _, _ := strings.Cut(pullHref(base, repo, num), "?")
	q := url.Values{"dir": {ref.Dir}, "workspace": {ref.Workspace}}
	if ref.Name != "" {
		q.Set("project", ref.Name)
	}
	if repo.VCSHost != "" {
		q.Set("host", repo.VCSHost)
	}
	return href + "/plan?" + q.Encode()
}

// planGroup is the resources of a plan that share an action.
type planGroup struct {
	Action PlanAction
	Label  string
	Symbol string
	// Class colors the symbol: a (add), c (change), d (destroy), r (replace)
	// or o (other).
	Class string
	// Filter is the filter chip that shows the group.
	Filter    string
	Resources []ResourceChange
}

// planGroupOrder puts the riskiest changes first.
var planGroupOrder = []planGroup{
	{Action: PlanDelete, Label: "Destroy", Symbol: "-", Class: "d", Filter: "destroy"},
	{Action: PlanReplace, Label: "Replace", Symbol: "±", Class: "r", Filter: "replace"},
	{Action: PlanUpdate, Label: "Change", Symbol: "~", Class: "c", Filter: "change"},
	{Action: PlanCreate, Label: "Add", Symbol: "+", Class: "a", Filter: "add"},
	{Action: PlanForget, Label: "Remove from state", Symbol: "∅", Class: "o", Filter: "other"},
	{Action: PlanImport, Label: "Import", Symbol: "↓", Class: "o", Filter: "other"},
	{Action: PlanMove, Label: "Move", Symbol: "→", Class: "o", Filter: "other"},
	{Action: PlanRead, Label: "Read data source", Symbol: "≤", Class: "o", Filter: "other"},
}

func planGroups(p ParsedPlan) []planGroup {
	var out []planGroup
	for _, g := range planGroupOrder {
		for _, r := range p.Resources {
			if r.Action == g.Action {
				g.Resources = append(g.Resources, r)
			}
		}
		if len(g.Resources) > 0 {
			out = append(out, g)
		}
	}
	return out
}

type planFilter struct {
	Key   string
	Label string
	Count int
}

// planFilters lists the filter chips with how many listed resources each
// shows. Chips with nothing to show are left out, except All.
func planFilters(groups []planGroup) []planFilter {
	out := []planFilter{{Key: "all", Label: "All"}}
	for _, f := range []planFilter{{Key: "add", Label: "Add"}, {Key: "change", Label: "Change"}, {Key: "destroy", Label: "Destroy"}, {Key: "replace", Label: "Replace"}, {Key: "other", Label: "Other"}} {
		for _, g := range groups {
			if g.Filter == f.Key {
				f.Count += len(g.Resources)
			}
		}
		out[0].Count += f.Count
		if f.Count > 0 {
			out = append(out, f)
		}
	}
	return out
}

// planMessage explains why a project's plan details can't be shown.
func planMessage(p ProjectPlan, state ProjectState) (title, body string) {
	switch p.Status {
	case PlanNoJSON:
		return "Atlantis didn't save this plan as JSON",
			"Plan details come from the show step, which saves the plan as JSON. It runs as part of policy checks. Without policy checks, add a show step after plan in the project's workflow, then run atlantis plan again."
	case PlanOutdated:
		if state == StatePlanFailed {
			return "The latest plan failed", "The plan JSON on this replica is from an earlier plan. Fix the error in the plan log, then run atlantis plan again."
		}
		return "The plan JSON is from an earlier plan", "The saved plan is newer than its JSON, so these details would be wrong. Run atlantis plan again with the show step in the workflow."
	case PlanTooLarge:
		return "This plan is too large to show here",
			fmt.Sprintf("The plan JSON is %d MB and the web UI reads up to %d MB. Read the plan in the job log or the pull request comment.", p.Size>>20, MaxPlanJSONBytes>>20)
	case PlanUnreadable:
		return "Atlantis couldn't read the plan JSON", "The file isn't a Terraform plan, or it changed while Atlantis read it. Run atlantis plan again."
	}
	return "There's no saved plan for this project on this replica",
		"It may have been applied or discarded, or planned on another replica. Run atlantis plan to plan it again."
}

// actionSentence says what the plan does to a resource, and why when
// Terraform says.
func actionSentence(r ResourceChange) string {
	s := actionVerb(r)
	if r.Reason != "" {
		s += " because " + r.Reason
	}
	return s + "."
}

func actionVerb(r ResourceChange) string {
	switch r.Action {
	case PlanCreate:
		return "Terraform will create this resource"
	case PlanUpdate:
		return "Terraform will update this resource in place"
	case PlanDelete:
		return "Terraform will destroy this resource"
	case PlanReplace:
		return "Terraform will replace this resource"
	case PlanForget:
		return "Terraform will remove this resource from state without destroying it"
	case PlanImport:
		return "Terraform will import this resource without changing it"
	case PlanMove:
		return "Terraform will move this resource to a new address without changing it"
	case PlanRead:
		return "Terraform will read this data source during apply"
	}
	return "Terraform will change this resource"
}
