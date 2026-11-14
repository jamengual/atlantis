// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"net/http"
	"strings"
	"time"
)

// driftStaleAfter is how old a drift check can be before the page flags it.
// Drift detection runs on whatever schedule calls the API, so a check older
// than a day usually means the schedule stopped.
const driftStaleAfter = 24 * time.Hour

// driftFilters are the filter chips on the drift page.
var driftFilters = []struct{ Key, Label string }{
	{"", "All"},
	{"drifted", "Drifted"},
	{"failed", "Check failed"},
	{"in_sync", "In sync"},
	{"stale", "Not checked in a day"},
}

type driftCounts struct {
	Total, Drifted, Failed, InSync, Stale int
}

func countDrift(now time.Time, checks []DriftCheck) driftCounts {
	c := driftCounts{Total: len(checks)}
	for _, d := range checks {
		switch d.Status() {
		case DriftDrifted:
			c.Drifted++
		case DriftFailed:
			c.Failed++
		case DriftInSync:
			c.InSync++
		}
		if driftStale(now, d) {
			c.Stale++
		}
	}
	return c
}

func driftStale(now time.Time, d DriftCheck) bool {
	return now.Sub(d.CheckedAt) > driftStaleAfter
}

func matchesDriftFilter(now time.Time, d DriftCheck, filter string) bool {
	switch filter {
	case "drifted":
		return d.Status() == DriftDrifted
	case "failed":
		return d.Error != ""
	case "in_sync":
		return d.Status() == DriftInSync
	case "stale":
		return driftStale(now, d)
	}
	return true
}

// driftPlan links a drift check to an open pull request that plans the same
// project, where the plan page shows its resource changes.
type driftPlan struct {
	Num  int
	Href string
}

type driftRow struct {
	Check DriftCheck
	Stale bool
	Plans []driftPlan
}

type driftData struct {
	Enabled bool
	Rows    []driftRow
	Filter  string
	Counts  driftCounts
}

// driftPlans finds the open pull requests that plan the checked project.
func driftPlans(base string, d DriftCheck, pulls []PullRequest) []driftPlan {
	var out []driftPlan
	for _, p := range pulls {
		if !strings.EqualFold(p.Repo.FullName, d.Repo.FullName) || !sameHost(p.Repo.VCSHost, d.Repo.VCSHost) {
			continue
		}
		for _, proj := range p.Projects {
			if proj.Dir != d.Dir || proj.Workspace != d.Workspace {
				continue
			}
			if d.ProjectName != "" && proj.Name != "" && proj.Name != d.ProjectName {
				continue
			}
			out = append(out, driftPlan{Num: p.Num, Href: planHref(base, p.Repo, p.Num, proj.Ref())})
			break
		}
	}
	return out
}

func (h *Handler) drift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	report, err := h.Store.ListDrift(ctx)
	if err != nil {
		h.fail(w, r, "drift results", err)
		return
	}
	pulls, err := h.Store.ListPulls(ctx)
	if err != nil {
		h.fail(w, r, "pull requests", err)
		return
	}
	filter := r.URL.Query().Get("state")
	known := false
	for _, f := range driftFilters {
		known = known || f.Key == filter
	}
	if !known {
		filter = ""
	}
	now := h.now()
	d := driftData{Enabled: report.Enabled, Filter: filter, Counts: countDrift(now, report.Checks)}
	for _, c := range report.Checks {
		if matchesDriftFilter(now, c, filter) {
			d.Rows = append(d.Rows, driftRow{Check: c, Stale: driftStale(now, c), Plans: driftPlans(h.BasePath, c, pulls)})
		}
	}
	l := loaded{pulls: pulls, drift: &report}
	l.have.pulls = true
	m := h.metaWith(r, l, "Drift", "drift", crumb{Label: "Drift"})
	h.render(w, r, http.StatusOK, driftPage(m, d))
}
