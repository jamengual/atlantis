// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webauth/webauthtest"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

// unlockStore has two pull requests that hold two locks each, in a normal
// repo and a prod repo, and one lock left by a closed pull request.
func unlockStore() *fakeStore {
	s := sampleStore()
	infra := webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}
	prod := webui.Repository{VCSHost: "github.com", FullName: "acme/prod-network"}
	s.pulls = append(s.pulls, webui.PullRequest{Repo: prod, Num: 9, Author: "kchen",
		Projects: []webui.Project{{Dir: "vpc", Workspace: "default", State: webui.StatePlanned, LockID: "acme/prod-network/vpc/default"}}})
	s.locks = []webui.Lock{
		{ID: "acme/infra/network/default", Repo: infra, Dir: "network", Workspace: "default", PullNum: 1482, User: "mrivera", Since: now.Add(-4 * time.Minute), PullTracked: true},
		{ID: "acme/infra/dns/default", Repo: infra, Dir: "dns", Workspace: "default", PullNum: 1482, User: "mrivera", Since: now.Add(-5 * time.Minute), PullTracked: true},
		{ID: "acme/prod-network/vpc/default", Repo: prod, Dir: "vpc", Workspace: "default", PullNum: 9, User: "kchen", Since: now.Add(-6 * time.Minute), PullTracked: true},
		{ID: "acme/prod-network/tgw/default", Repo: prod, Dir: "tgw", Workspace: "default", PullNum: 9, User: "kchen", Since: now.Add(-7 * time.Minute), PullTracked: true},
		{ID: "acme/data/old/default", Repo: webui.Repository{FullName: "acme/data"}, Dir: "old", Workspace: "default", PullNum: 62, User: "sokafor", Since: now.Add(-9 * 24 * time.Hour)},
	}
	return s
}

func postBody(t *testing.T, srv *httptest.Server, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	Ok(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("alice", "pw")
	resp, err := noRedirectClient().Do(req)
	Ok(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestUnlockAll_PullPageListsTheLocks(t *testing.T) {
	srv := newServer(t, unlockStore(), &fakeActions{}, "")
	_, body := get(t, srv, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	assertContains(t, body, "Unlock all…", `name="pull" value="github.com|acme/infra|1482"`, "releases 2 locks", "Release 2 locks",
		`<span class="mono">network</span>`, `<span class="mono">dns</span>`)
	Assert(t, !strings.Contains(body, "vpc"), "locks of other pull requests are not listed")
}

func TestUnlockAll_DiscardsEveryLockOfThePull(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, unlockStore(), actions, "")
	ret := "/ui/repos/acme/infra/pulls/1482?host=github.com"
	resp, _ := postBody(t, srv, "/ui/locks/discard", url.Values{"pull": {"github.com|acme/infra|1482"}, "return": {ret}, "id": {"acme/data/old/default"}})
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, ret+"&done=unlocked&missing=0&n=2", resp.Header.Get("Location"))
	// Selected IDs are ignored when the form names a pull request.
	Equals(t, []string{"acme/infra/dns/default", "acme/infra/network/default"}, actions.discarded)
	Equals(t, []string{"alice", "alice"}, actions.actors)
}

func TestUnlockAll_PullWithoutLocks(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, unlockStore(), actions, "")
	resp, _ := postBody(t, srv, "/ui/locks/discard", url.Values{"pull": {"github.com|acme/infra|7"}})
	Equals(t, "/ui/locks?done=no-pull-locks", resp.Header.Get("Location"))
	_, body := get(t, srv, "/ui/locks?done=no-pull-locks")
	assertContains(t, body, "That pull request holds no locks now")
	for _, bad := range []string{"acme/infra|1482", "github.com|acme/infra|x", "github.com||1", "github.com|acme/infra|-1"} {
		resp, _ = postBody(t, srv, "/ui/locks/discard", url.Values{"pull": {bad}})
		Equals(t, http.StatusBadRequest, resp.StatusCode)
	}
	Equals(t, 0, len(actions.discarded))
}

func TestUnlockAll_LocksPageGroupsByPull(t *testing.T) {
	srv := newServer(t, unlockStore(), &fakeActions{}, "")
	_, body := get(t, srv, "/ui/locks")
	assertContains(t, body, `class="lockgroup"`, "acme/infra #1482", "acme/prod-network #9",
		`name="pull" value="github.com|acme/infra|1482"`, `name="pull" value="github.com|acme/prod-network|9"`, "Release 2 locks", "Release all…")
	// A pull request with one lock has no separate release-all control.
	Assert(t, !strings.Contains(body, `value="|acme/data|62"`), "single-lock groups need no release all")
	// The selection checkboxes are still there for every lock.
	Equals(t, 5, strings.Count(body, `name="id"`))
}

func TestUnlockAll_PartialFailureIsReported(t *testing.T) {
	actions := &fakeActions{failIDs: map[string]bool{"acme/infra/dns/default": true}, missing: map[string]bool{"gone": true}}
	srv := newServer(t, unlockStore(), actions, "")
	resp, body := postBody(t, srv, "/ui/locks/discard", url.Values{"id": {"acme/infra/dns/default", "acme/infra/network/default", "acme/data/old/default", "gone"}})
	Equals(t, http.StatusInternalServerError, resp.StatusCode)
	// The failure doesn't stop the others.
	Equals(t, []string{"acme/data/old/default", "acme/infra/network/default"}, actions.discarded)
	assertContains(t, body, "Some locks weren&#39;t unlocked", "Unlocked 2 and failed to unlock 1",
		"acme/infra #1482 dns", "redis: connection reset for acme/infra/dns/default",
		"acme/infra #1482 network", "acme/data #62 old", "1 lock was already unlocked", `href="/ui/locks"`)
}

// newUnlockPolicyServer serves the UI with OIDC sign-in where prod repos
// need an admin to unlock.
func newUnlockPolicyServer(t *testing.T, store *fakeStore, actions *fakeActions) (*httptest.Server, *webauthtest.OIDC) {
	t.Helper()
	idp := webauthtest.NewOIDC()
	t.Cleanup(idp.Server.Close)
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	public, _ := url.Parse(srv.URL)
	policy, err := webauth.NewPolicy(webauth.PolicyConfig{
		Rules: signInRoles,
		Repos: []valid.Repo{
			{IDRegex: regexp.MustCompile(`^github\.com/acme/prod-`), Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{Unlock: "admin"}}},
		},
	})
	Ok(t, err)
	provider, err := webauth.NewOIDCProvider(webauth.OIDCConfig{IssuerURL: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, Scopes: []string{"email"}})
	Ok(t, err)
	auth, err := webauth.NewManager(webauth.Config{PublicURL: public, SessionSecrets: []string{sessionSecret}, Providers: []webauth.LoginProvider{provider}, Policy: policy, Logger: logging.NewNoopLogger(t)})
	Ok(t, err)
	h := &webui.Handler{Store: store, Actions: actions, Logger: logging.NewNoopLogger(t), Now: func() time.Time { return now }, Auth: auth}
	r := mux.NewRouter()
	h.Register(r)
	handler = r
	return srv, idp
}

var (
	viewerClaims   = map[string]any{"sub": "v", "name": "Vera", "email": "vera@acme.com", "email_verified": true}
	operatorClaims = map[string]any{"sub": "o", "name": "Omar", "groups": []string{"sre"}}
	adminClaims    = map[string]any{"sub": "a", "name": "Ada", "groups": []string{"platform-admins"}}
)

func TestUnlockAll_EveryLockIsCheckedBeforeAnyIsDiscarded(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		form   url.Values
		allow  bool
	}{
		{"operator unlocks a normal pull", operatorClaims, url.Values{"pull": {"github.com|acme/infra|1482"}}, true},
		{"operator can't unlock a prod pull", operatorClaims, url.Values{"pull": {"github.com|acme/prod-network|9"}}, false},
		{"one prod lock in a selection stops all of it", operatorClaims, url.Values{"id": {"acme/infra/network/default", "acme/prod-network/vpc/default"}}, false},
		{"admin unlocks a prod pull", adminClaims, url.Values{"pull": {"github.com|acme/prod-network|9"}}, true},
		{"viewer can't unlock", viewerClaims, url.Values{"pull": {"github.com|acme/infra|1482"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := &fakeActions{}
			srv, idp := newUnlockPolicyServer(t, unlockStore(), actions)
			b := newBrowser(t, srv.URL)
			signIn(t, b, idp, tc.claims)
			resp := b.post(t, "/ui/locks/discard", tc.form)
			if tc.allow {
				Equals(t, http.StatusSeeOther, resp.StatusCode)
				Equals(t, 2, len(actions.discarded))
				Equals(t, tc.claims["name"], actions.actors[0])
			} else {
				Equals(t, http.StatusForbidden, resp.StatusCode)
				Equals(t, 0, len(actions.discarded))
			}
		})
	}
}

func TestUnlockAll_ControlsFollowThePolicy(t *testing.T) {
	srv, idp := newUnlockPolicyServer(t, unlockStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, operatorClaims)
	_, page := b.get(t, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	assertContains(t, page, "Unlock all…")
	_, page = b.get(t, "/ui/repos/acme/prod-network/pulls/9?host=github.com")
	Assert(t, !strings.Contains(page, "Unlock all…"), "operators can't unlock prod")
	_, locks := b.get(t, "/ui/locks")
	assertContains(t, locks, `value="github.com|acme/infra|1482"`)
	Assert(t, !strings.Contains(locks, `value="github.com|acme/prod-network|9"`), "no release-all for prod")
}

// ---------- maintenance windows ----------

func maintStore() *fakeStore {
	s := unlockStore()
	s.maint = []webui.MaintenanceWindow{
		{ID: "w1", Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Reason: "Upgrading the state bucket", By: "Ada", Since: now.Add(-10 * time.Minute), Until: now.Add(4 * time.Hour)},
		{ID: "w2", Repo: webui.Repository{FullName: "acme/data"}, Dir: "glue", Workspace: "prod", Plans: true, Reason: "INC-4211", By: "Omar", Since: now.Add(-time.Hour)},
	}
	return s
}

func TestMaintenance_PagesShowActiveWindows(t *testing.T) {
	srv := newServer(t, maintStore(), &fakeActions{}, "")
	_, overview := get(t, srv, "/ui")
	assertContains(t, overview, "2 maintenance windows are active.", "Upgrading the state bucket", "Whole repository · Applies frozen",
		"Directory glue, workspace prod · Plans and applies frozen", "Ends: In 4h (Nov 13 18:00 UTC)", "Ends: When someone ends it", `href="/ui/locks#maintenance"`)

	_, locks := get(t, srv, "/ui/locks")
	assertContains(t, locks, `id="maintenance"`, "Maintenance windows", "Upgrading the state bucket", "INC-4211",
		`action="/ui/maintenance/w1/end"`, "Start maintenance…", `<option value="acme/infra">`, "<option value=\"168h\">1 week</option>",
		"kept in memory on this replica")

	_, pull := get(t, srv, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	assertContains(t, pull, "1 maintenance window is active.", "Upgrading the state bucket")
	Assert(t, !strings.Contains(pull, "INC-4211"), "windows in other repos are not shown on a pull request")

	_, other := get(t, srv, "/ui/repos/acme/prod-network/pulls/9?host=github.com")
	Assert(t, !strings.Contains(other, "maintenance window"), "no banner without a window")
}

func TestMaintenance_NoWindows(t *testing.T) {
	srv := newServer(t, unlockStore(), &fakeActions{}, "")
	_, overview := get(t, srv, "/ui")
	Assert(t, !strings.Contains(overview, "maintenance window"), "no banner without windows")
	_, locks := get(t, srv, "/ui/locks")
	assertContains(t, locks, "No maintenance windows.")
}

func TestMaintenance_UserTextIsEscaped(t *testing.T) {
	store := maintStore()
	store.maint[0].Reason = `<script>alert("r")</script>`
	store.maint[0].By = `<img src=x onerror=alert(1)>`
	store.maint[0].Dir = `<b>dir</b>`
	srv := newServer(t, store, &fakeActions{}, "")
	for _, path := range []string{"/ui", "/ui/locks", "/ui/repos/acme/infra/pulls/1482?host=github.com"} {
		_, body := get(t, srv, path)
		Assert(t, !strings.Contains(body, `<script>alert("r")`) && !strings.Contains(body, "<img src=x") && !strings.Contains(body, "<b>dir</b>"), "%s: user text was not escaped", path)
		assertContains(t, body, "&lt;script&gt;alert(&#34;r&#34;)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;")
	}
}

func TestMaintenance_Start(t *testing.T) {
	store := unlockStore()
	actions := &fakeActions{store: store}
	srv := newServer(t, store, actions, "")
	resp, _ := postBody(t, srv, "/ui/maintenance", url.Values{
		"repo": {" acme/infra "}, "dir": {"network"}, "workspace": {"default"}, "project": {""}, "plans": {"on"},
		"reason": {"Upgrading the state bucket"}, "duration": {"4h"}, "return": {"/ui/locks"},
	})
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/locks?done=maint-started", resp.Header.Get("Location"))
	Equals(t, []webui.MaintenanceRequest{{
		Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "network", Workspace: "default",
		Plans: true, Reason: "Upgrading the state bucket", Until: now.Add(4 * time.Hour),
	}}, actions.started)
	Equals(t, []string{"alice"}, actions.startBy)
	_, body := get(t, srv, "/ui/locks?done=maint-started")
	assertContains(t, body, "Maintenance window started.", "Directory network, workspace default")

	// No end time, applies only, and a repo Atlantis doesn't know yet, which
	// then covers every host.
	resp, _ = postBody(t, srv, "/ui/maintenance", url.Values{"repo": {"acme/new"}, "reason": {"x"}, "duration": {""}})
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, webui.MaintenanceRequest{Repo: webui.Repository{FullName: "acme/new"}, Reason: "x"}, actions.started[1])
}

func TestMaintenance_StartRejectsBadInput(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, unlockStore(), actions, "")
	resp, body := postBody(t, srv, "/ui/maintenance", url.Values{"repo": {"acme/infra"}, "reason": {"x"}, "duration": {"9999h"}})
	Equals(t, http.StatusBadRequest, resp.StatusCode)
	assertContains(t, body, "Choose when the maintenance window ends")
	Equals(t, 0, len(actions.started))

	actions.startErr = errors.New("a reason is required, so people know why their commands are blocked")
	resp, body = postBody(t, srv, "/ui/maintenance", url.Values{"repo": {"acme/infra"}, "duration": {"1h"}})
	Equals(t, http.StatusBadRequest, resp.StatusCode)
	assertContains(t, body, "The maintenance window wasn't started: a reason is required")
}

func TestMaintenance_End(t *testing.T) {
	store := maintStore()
	actions := &fakeActions{store: store}
	srv := newServer(t, store, actions, "")
	resp, _ := postBody(t, srv, "/ui/maintenance/w1/end", url.Values{"return": {"/ui"}})
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui?done=maint-ended", resp.Header.Get("Location"))
	Equals(t, []string{"w1"}, actions.ended)
	resp, _ = postBody(t, srv, "/ui/maintenance/w1/end", nil)
	Equals(t, "/ui/locks?done=maint-gone", resp.Header.Get("Location"))
}

func TestMaintenance_RejectsCrossOrigin(t *testing.T) {
	store := maintStore()
	actions := &fakeActions{store: store}
	srv := newServer(t, store, actions, "")
	for _, path := range []string{"/ui/maintenance", "/ui/maintenance/w1/end"} {
		resp := post(t, srv, path, url.Values{"repo": {"acme/infra"}, "reason": {"x"}, "duration": {""}}, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
		Equals(t, http.StatusForbidden, resp.StatusCode)
	}
	Equals(t, 0, len(actions.started))
	Equals(t, 0, len(actions.ended))
}

func TestMaintenance_OnlyAdminsByDefault(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		allow  bool
	}{
		{"viewer", viewerClaims, false},
		{"operator", operatorClaims, false},
		{"admin", adminClaims, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := maintStore()
			actions := &fakeActions{store: store}
			srv, idp := newUnlockPolicyServer(t, store, actions)
			b := newBrowser(t, srv.URL)
			signIn(t, b, idp, tc.claims)

			_, locks := b.get(t, "/ui/locks")
			assertContains(t, locks, "Upgrading the state bucket")
			Equals(t, tc.allow, strings.Contains(locks, "Start maintenance…"))
			Equals(t, tc.allow, strings.Contains(locks, `action="/ui/maintenance/w1/end"`))

			start := b.post(t, "/ui/maintenance", url.Values{"repo": {"acme/infra"}, "reason": {"freeze"}, "duration": {"1h"}})
			end := b.post(t, "/ui/maintenance/w1/end", nil)
			if tc.allow {
				Equals(t, http.StatusSeeOther, start.StatusCode)
				Equals(t, http.StatusSeeOther, end.StatusCode)
				Equals(t, []string{"Ada"}, actions.startBy)
				Equals(t, []string{"w1"}, actions.ended)
			} else {
				Equals(t, http.StatusForbidden, start.StatusCode)
				Equals(t, http.StatusForbidden, end.StatusCode)
				Equals(t, 0, len(actions.started))
				Equals(t, 0, len(actions.ended))
			}
			_, access := b.get(t, "/ui/access")
			assertContains(t, access, "Start and end maintenance windows that freeze applies")
		})
	}
}

func TestGroupedLocksKeepNewestFirst(t *testing.T) {
	srv := newServer(t, unlockStore(), &fakeActions{}, "")
	_, body := get(t, srv, "/ui/locks")
	order := []string{"acme/infra #1482", "acme/prod-network #9", "acme/data #62"}
	pos := make([]int, len(order))
	for i, o := range order {
		pos[i] = strings.Index(body, "<b>"+o+"</b>")
		Assert(t, pos[i] >= 0, "group %q missing", o)
	}
	Assert(t, slices.IsSorted(pos), "groups out of order: %v", pos)
}
