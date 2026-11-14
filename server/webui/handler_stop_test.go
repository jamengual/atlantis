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

// stopStore has running jobs in three repos and a finished one.
func stopStore() *fakeStore {
	s := sampleStore()
	host := func(name string) webui.Repository { return webui.Repository{VCSHost: "github.com", FullName: name} }
	s.jobs = []webui.Job{
		{ID: "infra-plan", Repo: host("acme/infra"), PullNum: 1482, Dir: "network", Workspace: "default", Step: "plan", Lines: 3, LastOutput: now.Add(-time.Minute)},
		{ID: "prod-apply", Repo: host("acme/prod-network"), PullNum: 9, Dir: "vpc", Workspace: "default", Step: "apply", Lines: 8, LastOutput: now.Add(-time.Minute)},
		{ID: "lake-plan", Repo: host("acme/data-lake"), PullNum: 77, Dir: "glue", Workspace: "default", Step: "plan", Lines: 1, LastOutput: now.Add(-time.Minute)},
		{ID: "done-plan", Repo: host("acme/infra"), PullNum: 1482, Dir: "dns", Workspace: "default", Step: "plan", Done: true, LastOutput: now.Add(-time.Hour)},
		{ID: "hostless", Repo: webui.Repository{FullName: "acme/infra"}, PullNum: 1482, Dir: "edge", Workspace: "prod", Step: "plan", LastOutput: now.Add(-time.Minute)},
	}
	s.logs = map[string][]string{"infra-plan": {"Refreshing state..."}}
	return s
}

func sameOrigin() map[string]string { return map[string]string{"Sec-Fetch-Site": "same-origin"} }

func TestStopJob_StopsARunningJob(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, stopStore(), actions, "")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ui/jobs/infra-plan/stop", strings.NewReader(url.Values{"return": {"/ui/jobs"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("alice", "pw")
	resp, err := noRedirectClient().Do(req)
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/jobs?done=stop-requested", resp.Header.Get("Location"))
	// The PR comment and the job log name the person who stopped it.
	Equals(t, map[string]string{"infra-plan": "alice"}, actions.stops)

	_, body := get(t, srv, "/ui/jobs?done=stop-requested")
	assertContains(t, body, "Stop requested. Terraform got an interrupt")
}

func TestStopJob_DefaultReturnIsTheJobPage(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, stopStore(), actions, "/atlantis")
	resp := post(t, srv, "/ui/jobs/infra-plan/stop", nil, sameOrigin())
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/atlantis/ui/jobs/infra-plan?done=stop-requested", resp.Header.Get("Location"))
	// Without sign-in or basic auth, the stop still says someone did it.
	Equals(t, "an anonymous user", actions.stops["infra-plan"])
}

func TestStopJob_AlreadyStopping(t *testing.T) {
	actions := &fakeActions{stops: map[string]string{"infra-plan": "bob"}}
	srv := newServer(t, stopStore(), actions, "")
	resp := post(t, srv, "/ui/jobs/infra-plan/stop", nil, sameOrigin())
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/jobs/infra-plan?done=already-stopping", resp.Header.Get("Location"))
	Equals(t, "bob", actions.stops["infra-plan"])
}

func TestStopJob_FinishedJob(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, stopStore(), actions, "")
	resp := post(t, srv, "/ui/jobs/done-plan/stop", nil, sameOrigin())
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/jobs/done-plan?done=stop-finished", resp.Header.Get("Location"))
	Equals(t, 0, len(actions.stops))
}

func TestStopJob_UnknownJobIsOnAnotherReplica(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, stopStore(), actions, "")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ui/jobs/elsewhere/stop", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := noRedirectClient().Do(req)
	Ok(t, err)
	defer resp.Body.Close()
	Equals(t, http.StatusNotFound, resp.StatusCode)
	b, _ := io.ReadAll(resp.Body)
	assertContains(t, string(b), "This replica isn't running that job", "Only the replica that runs a job can stop it")
	Equals(t, 0, len(actions.stops))
}

func TestStopJob_RejectsCrossOrigin(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, stopStore(), actions, "")
	resp := post(t, srv, "/ui/jobs/infra-plan/stop", nil, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
	Equals(t, http.StatusForbidden, resp.StatusCode)
	Equals(t, 0, len(actions.stops))
	// GET doesn't stop anything either.
	r, _ := get(t, srv, "/ui/jobs/infra-plan/stop")
	Equals(t, http.StatusMethodNotAllowed, r.StatusCode)
	Equals(t, 0, len(actions.stops))
}

func TestStopJob_Error(t *testing.T) {
	srv := newServer(t, stopStore(), &fakeActions{stopErr: errors.New("registry gone")}, "")
	resp := post(t, srv, "/ui/jobs/infra-plan/stop", nil, sameOrigin())
	Equals(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestStopJob_PagesShowTheControlAndState(t *testing.T) {
	store := stopStore()
	store.jobs[0].Stop = &webui.JobStop{By: `<script>alert("x")</script>`, At: now.Add(-30 * time.Second)}
	store.jobs[3].Stop = &webui.JobStop{By: "bob", At: now.Add(-time.Hour), Killed: true}
	srv := newServer(t, store, &fakeActions{}, "")

	// A running job that nobody stopped has the control.
	_, body := get(t, srv, "/ui/jobs/lake-plan")
	assertContains(t, body, `action="/ui/jobs/lake-plan/stop"`, "Stop job", "only this replica can stop it")

	// A job being stopped says so, with the name escaped, and has no control.
	_, body = get(t, srv, "/ui/jobs/infra-plan")
	assertContains(t, body, "Stopping", "Stopped by &lt;script&gt;", "is finishing the operations in progress")
	Assert(t, !strings.Contains(body, `<script>alert`), "stopper name was not escaped")
	Assert(t, !strings.Contains(body, "/ui/jobs/infra-plan/stop"), "a stopping job should not offer another stop")

	// A killed job warns about the state lock.
	_, body = get(t, srv, "/ui/jobs/done-plan")
	assertContains(t, body, "Stopped", "Stopped by bob", "force-unlock")
	Assert(t, !strings.Contains(body, "/ui/jobs/done-plan/stop"), "a finished job should not offer a stop")

	// Lists offer the control for running jobs only.
	_, body = get(t, srv, "/ui/jobs")
	assertContains(t, body, `action="/ui/jobs/lake-plan/stop"`, `action="/ui/jobs/prod-apply/stop"`, "by bob", "Only the replica running a job can stop it")
	Assert(t, !strings.Contains(body, "/ui/jobs/done-plan/stop"), "finished job offered a stop")
	_, body = get(t, srv, "/ui")
	assertContains(t, body, `action="/ui/jobs/lake-plan/stop"`, `name="return" value="/ui"`)
}

func TestStopJob_LogStreamEndsWithWhoStoppedIt(t *testing.T) {
	store := stopStore()
	store.jobs[0].Stop = &webui.JobStop{By: "Ada\nAdmin", At: now}
	srv := newServer(t, store, &fakeActions{}, "")
	body := readEvents(t, srv, "/ui/jobs/infra-plan/events", "")
	assertContains(t, body, "data: Refreshing state...", "event: done\ndata: Stopped by Ada Admin\n")

	plain := readEvents(t, srv, "/ui/jobs/lake-plan/events", "")
	assertContains(t, plain, "event: done\ndata: \n")
}

// newPolicyServer serves the UI with OIDC sign-in and a repo-aware policy:
// operators stop jobs, prod repos need admin, and data-eng operates the
// data lake only.
func newPolicyServer(t *testing.T, store *fakeStore, actions *fakeActions) (*httptest.Server, *webauthtest.OIDC) {
	t.Helper()
	idp := webauthtest.NewOIDC()
	t.Cleanup(idp.Server.Close)
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	public, _ := url.Parse(srv.URL)
	policy, err := webauth.NewPolicy(webauth.PolicyConfig{
		Flags: signInRoles,
		Repos: []valid.Repo{
			{IDRegex: regexp.MustCompile(".*")},
			{ID: "github.com/acme/data-lake", Access: &valid.RepoAccess{Roles: valid.AccessRoles{Operator: []valid.AccessRule{{Group: "data-eng"}}}}},
			{IDRegex: regexp.MustCompile(`^github\.com/acme/prod-`), Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{StopJob: "admin"}}},
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

func TestStopJob_RolesAndRepos(t *testing.T) {
	viewer := map[string]any{"sub": "v", "name": "Vera", "email": "vera@acme.com", "email_verified": true}
	dataEng := map[string]any{"sub": "d", "name": "Dana", "email": "dana@acme.com", "email_verified": true, "groups": []string{"data-eng"}}
	operator := map[string]any{"sub": "o", "name": "Omar", "groups": []string{"sre"}}
	admin := map[string]any{"sub": "a", "name": "Ada", "groups": []string{"platform-admins"}}
	cases := []struct {
		name   string
		claims map[string]any
		job    string
		allow  bool
	}{
		{"viewer can't stop", viewer, "infra-plan", false},
		{"operator stops", operator, "infra-plan", true},
		{"prod needs admin", operator, "prod-apply", false},
		{"admin stops prod", admin, "prod-apply", true},
		{"repo grant stops its repo", dataEng, "lake-plan", true},
		{"repo grant doesn't reach other repos", dataEng, "infra-plan", false},
		{"unknown host needs admin", operator, "hostless", false},
		{"admin stops a job with an unknown host", admin, "hostless", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := &fakeActions{}
			srv, idp := newPolicyServer(t, stopStore(), actions)
			b := newBrowser(t, srv.URL)
			signIn(t, b, idp, tc.claims)

			_, page := b.get(t, "/ui/jobs/"+tc.job)
			Equals(t, tc.allow, strings.Contains(page, "/ui/jobs/"+tc.job+"/stop"))
			_, list := b.get(t, "/ui/jobs")
			Equals(t, tc.allow, strings.Contains(list, "/ui/jobs/"+tc.job+"/stop"))

			resp := b.post(t, "/ui/jobs/"+tc.job+"/stop", nil)
			if tc.allow {
				Equals(t, http.StatusSeeOther, resp.StatusCode)
				Equals(t, tc.claims["name"], actions.stops[tc.job])
			} else {
				Equals(t, http.StatusForbidden, resp.StatusCode)
				Equals(t, 0, len(actions.stops))
			}
		})
	}
}

func TestStopJob_AccessPageShowsTheRule(t *testing.T) {
	srv, idp := newPolicyServer(t, stopStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, map[string]any{"sub": "o", "name": "Omar", "groups": []string{"sre"}})
	_, body := b.get(t, "/ui/access")
	assertContains(t, body, "Stop running plans, applies, and hooks", "Stopping jobs needs", "You can stop jobs")
}
