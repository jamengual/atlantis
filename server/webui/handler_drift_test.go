// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

func driftStore() *fakeStore {
	s := sampleStore()
	infra := webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}
	s.drift = webui.DriftReport{Enabled: true, Checks: []webui.DriftCheck{
		{Repo: infra, Dir: "dns", Workspace: "default", Ref: "main", Commit: "c0ffee1234567", Drifted: true, ChangesOutside: true,
			Changes: webui.Changes{Known: true, Add: 1, Change: 3, Destroy: 2}, Summary: "Plan: 1 to add, 3 to change, 2 to destroy.", CheckedAt: now.Add(-2 * time.Hour)},
		{Repo: infra, Dir: "edge", Workspace: "prod", ProjectName: "edge-prod", Ref: "main", Error: "running terraform plan: exit status 1", CheckedAt: now.Add(-3 * time.Hour)},
		{Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/data"}, Dir: "glue", Workspace: "default", Ref: "v1.2.0", BaseBranch: "main",
			Changes: webui.Changes{Known: true}, CheckedAt: now.Add(-50 * time.Hour)},
	}}
	return s
}

func TestDrift_Page(t *testing.T) {
	srv := newServer(t, driftStore(), &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/drift")
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, body,
		"<title>Drift · Atlantis</title>",
		"3 of 3 projects",
		`data-drift="drifted"`, "Drifted", "Changed outside Terraform", "+1", "~3", "-2", "c0ffee1", "2h ago",
		`data-drift="failed"`, "Check failed", "running terraform plan: exit status 1", "edge-prod",
		`data-drift="in_sync"`, "In sync", "v1.2.0 on main", "2d ago", "Stale",
		// The drifted dns project is planned in an open pull request, so it
		// links to that plan.
		`href="/ui/repos/acme/infra/pulls/1482/plan?dir=dns&amp;host=github.com&amp;workspace=default"`, "Plan in #1482",
		"kept in memory on the replica that ran the detection",
	)
	// Drifted first, then failed, then in sync.
	Assert(t, strings.Index(body, `data-drift="drifted"`) < strings.Index(body, `data-drift="failed"`), "drifted must come before failed")
	Assert(t, strings.Index(body, `data-drift="failed"`) < strings.Index(body, `data-drift="in_sync"`), "failed must come before in sync")
	// The nav counts drifted projects.
	assertContains(t, body, `href="/ui/drift" aria-current="page"`)
}

func TestDrift_Filters(t *testing.T) {
	srv := newServer(t, driftStore(), &fakeActions{}, "")
	cases := []struct {
		query string
		want  []string
		count string
	}{
		{"?state=drifted", []string{`data-drift="drifted"`}, "1 of 3 projects"},
		{"?state=failed", []string{`data-drift="failed"`}, "1 of 3 projects"},
		{"?state=in_sync", []string{`data-drift="in_sync"`}, "1 of 3 projects"},
		{"?state=stale", []string{`data-drift="in_sync"`}, "1 of 3 projects"},
		{"?state=bogus", []string{`data-drift="drifted"`, `data-drift="failed"`, `data-drift="in_sync"`}, "3 of 3 projects"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			_, body := get(t, srv, "/ui/drift"+c.query)
			assertContains(t, body, c.count)
			assertContains(t, body, c.want...)
			Equals(t, len(c.want), strings.Count(body, "data-drift="))
		})
	}
}

func TestDrift_Disabled(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/drift")
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, body, "Drift detection is off on this server", "--enable-drift-detection")
	// The overview has no drift card when detection is off.
	_, overview := get(t, srv, "/ui")
	Assert(t, !strings.Contains(overview, `id="drift-h"`), "overview shows a drift card while drift detection is off")
}

func TestDrift_NoChecksYet(t *testing.T) {
	store := sampleStore()
	store.drift = webui.DriftReport{Enabled: true}
	srv := newServer(t, store, &fakeActions{}, "")
	_, body := get(t, srv, "/ui/drift")
	assertContains(t, body, "No drift checks yet on this replica", "POST /api/drift/detect")
}

func TestDrift_Overview(t *testing.T) {
	srv := newServer(t, driftStore(), &fakeActions{}, "")
	_, body := get(t, srv, "/ui")
	assertContains(t, body, `id="drift-h"`, "Latest check of each project on this replica", `href="/ui/drift"`)
	// One drifted, one failed, one in sync, one stale.
	Equals(t, 4, strings.Count(body, `<b class="num">1</b>`))
}

func TestDrift_ReadError(t *testing.T) {
	store := driftStore()
	store.driftErr = errors.New("drift storage unavailable")
	srv := newServer(t, store, &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/drift")
	Equals(t, http.StatusServiceUnavailable, resp.StatusCode)
	assertContains(t, body, "drift storage unavailable")
	// The overview still loads.
	resp, _ = get(t, srv, "/ui")
	Equals(t, http.StatusOK, resp.StatusCode)
}

func TestDrift_EscapesUserData(t *testing.T) {
	store := sampleStore()
	xss := `<script>alert(1)</script>`
	store.drift = webui.DriftReport{Enabled: true, Checks: []webui.DriftCheck{{
		Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/" + xss}, Dir: "d" + xss, Workspace: "w" + xss,
		ProjectName: "p" + xss, Ref: "r" + xss, BaseBranch: "b" + xss, Commit: xss, Error: "e" + xss, CheckedAt: now,
	}}}
	srv := newServer(t, store, &fakeActions{}, "")
	_, body := get(t, srv, "/ui/drift")
	Assert(t, !strings.Contains(body, xss), "drift page rendered unescaped user data")
	assertContains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestDrift_Permissions(t *testing.T) {
	srv, idp := newSignInServer(t, driftStore(), &fakeActions{})

	viewer := newBrowser(t, srv.URL)
	signIn(t, viewer, idp, map[string]any{"sub": "v", "name": "Vera Viewer", "email": "vera@acme.com", "email_verified": true})
	status, body := viewer.get(t, "/ui/drift")
	Equals(t, http.StatusOK, status)
	assertContains(t, body, "3 of 3 projects")

	// Someone without a role can't sign in, so the page sends them to the
	// sign-in page and shows no drift results.
	nobody := newBrowser(t, srv.URL)
	idp.SetUser(map[string]any{"sub": "x", "name": "Xavier Outsider", "email": "x@example.com", "email_verified": true})
	status, body = nobody.get(t, "/ui/login/oidc?return=%2Fui%2Fdrift")
	Equals(t, http.StatusForbidden, status)
	Assert(t, !strings.Contains(body, "acme/infra"), "a person without a role saw drift results")
	resp, err := nobody.noFollow().Get(srv.URL + "/ui/drift")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/login?return=%2Fui%2Fdrift", resp.Header.Get("Location"))
}
