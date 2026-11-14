// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

var now = time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)

type fakeStore struct {
	pulls    []webui.PullRequest
	locks    []webui.Lock
	jobs     []webui.Job
	apply    webui.ApplyLock
	logs     map[string][]string
	liveLogs map[string]chan webui.LogLine
	plans    map[webui.ProjectRef]*webui.ProjectPlan
	err      error
}

func (f *fakeStore) Capabilities() webui.Capabilities { return webui.Capabilities{} }
func (f *fakeStore) Instance(context.Context) webui.Instance {
	return webui.Instance{Version: "9.9.9", LockingBackend: "redis", DatabaseOK: true, InProgressOps: 3}
}
func (f *fakeStore) ListPulls(context.Context) ([]webui.PullRequest, error) { return f.pulls, f.err }
func (f *fakeStore) GetPull(_ context.Context, repo webui.Repository, num int) (*webui.PullRequest, error) {
	for i := range f.pulls {
		if f.pulls[i].Repo.FullName == repo.FullName && f.pulls[i].Num == num && (repo.VCSHost == "" || repo.VCSHost == f.pulls[i].Repo.VCSHost) {
			return &f.pulls[i], nil
		}
	}
	return nil, f.err
}
func (f *fakeStore) GetPlan(ctx context.Context, repo webui.Repository, num int, ref webui.ProjectRef) (*webui.ProjectPlan, error) {
	p, err := f.GetPull(ctx, repo, num)
	if p == nil {
		return nil, err
	}
	for _, proj := range p.Projects {
		if proj.Ref() == ref {
			if plan, ok := f.plans[ref]; ok {
				return plan, f.err
			}
			return &webui.ProjectPlan{Status: webui.PlanNoJSON}, f.err
		}
	}
	return nil, f.err
}
func (f *fakeStore) ListLocks(context.Context) ([]webui.Lock, error)    { return f.locks, f.err }
func (f *fakeStore) ApplyLock(context.Context) (webui.ApplyLock, error) { return f.apply, nil }
func (f *fakeStore) ListJobs(_ context.Context, jf webui.JobFilter) []webui.Job {
	var out []webui.Job
	for _, j := range f.jobs {
		if jf.RunningOnly && j.Done {
			continue
		}
		out = append(out, j)
	}
	return out
}
func (f *fakeStore) GetJob(_ context.Context, id string) (webui.Job, bool) {
	for _, j := range f.jobs {
		if j.ID == id {
			return j, true
		}
	}
	return webui.Job{}, false
}
func (f *fakeStore) JobLog(ctx context.Context, id string, from int) <-chan webui.LogLine {
	if live, ok := f.liveLogs[id]; ok {
		return live
	}
	ch := make(chan webui.LogLine, len(f.logs[id]))
	for i, l := range f.logs[id] {
		if i >= from {
			ch <- webui.LogLine{N: i + 1, Text: l}
		}
	}
	close(ch)
	return ch
}

type fakeActions struct {
	mu        sync.Mutex
	discarded []string
	actors    []string
	locked    int
	unlocked  int
	missing   map[string]bool
	err       error
	// stops records StopJob calls by job ID, with the actor.
	stops   map[string]string
	stopErr error
}

func (f *fakeActions) StopJob(id, actor string) (webui.JobStop, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return webui.JobStop{}, false, f.stopErr
	}
	if by, ok := f.stops[id]; ok {
		return webui.JobStop{By: by, At: now}, false, nil
	}
	if f.stops == nil {
		f.stops = map[string]string{}
	}
	f.stops[id] = actor
	return webui.JobStop{By: actor, At: now}, true, nil
}

func (f *fakeActions) DiscardLock(id, actor string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if f.missing[id] {
		return false, nil
	}
	f.discarded = append(f.discarded, id)
	f.actors = append(f.actors, actor)
	return true, nil
}
func (f *fakeActions) LockApplies() error   { f.locked++; return f.err }
func (f *fakeActions) UnlockApplies() error { f.unlocked++; return f.err }

func sampleStore() *fakeStore {
	return &fakeStore{
		apply: webui.ApplyLock{Enabled: true},
		pulls: []webui.PullRequest{
			{
				Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Num: 1482,
				URL: "https://github.com/acme/infra/pull/1482", Author: "mrivera", HeadBranch: "alb-sg", BaseBranch: "main", HeadCommit: "a91f3c2deadbeef",
				LastActivity: now.Add(-4 * time.Minute),
				Projects: []webui.Project{
					{Dir: "network", Workspace: "default", State: webui.StateRunning, LockID: "acme/infra/network/default", LatestJobID: "job-1"},
					{Dir: "edge", Workspace: "prod", State: webui.StatePlanFailed},
					{Dir: "dns", Workspace: "default", State: webui.StatePlanned, Changes: webui.Changes{Known: true, Add: 2, Change: 4, Destroy: 1}},
				},
			},
			{
				Repo: webui.Repository{FullName: "acme/data"}, Num: 77, Author: "sokafor",
				Projects: []webui.Project{{Dir: "glue", Workspace: "default", State: webui.StatePolicyFailed}},
			},
		},
		locks: []webui.Lock{
			{ID: "acme/infra/network/default", Repo: webui.Repository{FullName: "acme/infra"}, Dir: "network", Workspace: "default", PullNum: 1482, User: "mrivera", Since: now.Add(-4 * time.Minute), PullTracked: true},
			{ID: "acme/data/old/default", Repo: webui.Repository{FullName: "acme/data"}, Dir: "old", Workspace: "default", PullNum: 62, User: "sokafor", Since: now.Add(-9 * 24 * time.Hour), PullTracked: false},
		},
		jobs: []webui.Job{
			{ID: "job-1", Repo: webui.Repository{FullName: "acme/infra"}, PullNum: 1482, Dir: "network", Workspace: "default", Step: "plan", Lines: 3, LastOutput: now.Add(-time.Minute)},
		},
		logs: map[string][]string{"job-1": {"$ terraform init", "Plan: 2 to add, 4 to change, 1 to destroy.", "multi\nline"}},
	}
}

func newServer(t *testing.T, store *fakeStore, actions *fakeActions, base string) *httptest.Server {
	t.Helper()
	h := &webui.Handler{
		Store:             store,
		Actions:           actions,
		BasePath:          base,
		Logger:            logging.NewNoopLogger(t),
		Now:               func() time.Time { return now },
		HeartbeatInterval: 20 * time.Millisecond,
	}
	r := mux.NewRouter()
	h.Register(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	Ok(t, err)
	defer resp.Body.Close()
	var b strings.Builder
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		b.WriteString(sc.Text())
		b.WriteString("\n")
	}
	return resp, b.String()
}

func assertContains(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("response does not contain %q", w)
		}
	}
}

func TestPages_Render(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	cases := []struct {
		path string
		want []string
	}{
		{"/ui", []string{"<title>Overview · Atlantis</title>", "Needs attention", "acme/infra #1482: plan failed in edge (prod)",
			"acme/data #77 is waiting for a policy approval", "pull request #62, which Atlantis no longer tracks", "Running now", "9.9.9"}},
		{"/ui/pulls", []string{"2 of 2 pull requests", "acme/infra #1482", "/ui/repos/acme/infra/pulls/1482?host=github.com"}},
		{"/ui/pulls?state=policy", []string{"1 of 2 pull requests", "acme/data #77"}},
		{"/ui/repos/acme/infra/pulls/1482", []string{"acme/infra #1482", "alb-sg → main", "a91f3c2", "+2", "~4", "-1", "Discard plan and unlock", "/ui/jobs/job-1"}},
		{"/ui/locks", []string{"2 project locks", "1 look abandoned", "Not tracked", "Stale", "value=\"acme/data/old/default\""}},
		{"/ui/jobs", []string{"1 jobs", "network", "Running"}},
		{"/ui/jobs/job-1", []string{"<log-view", "data-src=\"/ui/jobs/job-1/events\""}},
		{"/ui/replica", []string{"This replica", "Only in memory, until restart", "redis"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			resp, body := get(t, srv, c.path)
			Equals(t, http.StatusOK, resp.StatusCode)
			assertContains(t, body, c.want...)
		})
	}
}

func TestPages_SecurityHeaders(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	resp, body := get(t, srv, "/ui")
	csp := resp.Header.Get("Content-Security-Policy")
	assertContains(t, csp, "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'")
	Assert(t, !strings.Contains(csp, "unsafe"), "CSP must not allow unsafe sources: %s", csp)
	Equals(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	Equals(t, "DENY", resp.Header.Get("X-Frame-Options"))
	// No inline scripts or style attributes, so the strict CSP holds.
	Assert(t, !strings.Contains(body, "<script>"), "page has an inline script")
	Assert(t, !strings.Contains(body, " style=\""), "page has an inline style attribute")
}

func TestPages_EscapeUserContent(t *testing.T) {
	store := sampleStore()
	store.pulls[0].Author = "<script>alert(1)</script>"
	srv := newServer(t, store, &fakeActions{}, "")
	_, body := get(t, srv, "/ui/pulls")
	Assert(t, !strings.Contains(body, "<script>alert(1)</script>"), "author was not escaped")
	assertContains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestPages_BasePath(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "/atlantis")
	_, body := get(t, srv, "/ui/pulls")
	assertContains(t, body, `href="/atlantis/ui/repos/acme/infra/pulls/1482?host=github.com"`, `/atlantis/ui/static/app.css?v=`, `src="/atlantis/ui/static/atlantis-icon.png?v=`, `href="/atlantis/ui/static/favicon.png?v=`)
}

func TestPages_NotFound(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/repos/acme/infra/pulls/9")
	Equals(t, http.StatusNotFound, resp.StatusCode)
	assertContains(t, body, "Atlantis has nothing for this pull request")
	resp, body = get(t, srv, "/ui/jobs/nope")
	Equals(t, http.StatusNotFound, resp.StatusCode)
	assertContains(t, body, "This replica has no output for that job")
}

func TestPages_StoreErrorShowsRecovery(t *testing.T) {
	store := sampleStore()
	store.err = errors.New("dial tcp: connection refused")
	srv := newServer(t, store, &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/locks")
	Equals(t, http.StatusServiceUnavailable, resp.StatusCode)
	assertContains(t, body, "connection refused", "Check that the lock database is reachable")
}

func TestStatic_Served(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	for _, name := range []string{"app.css", "app.js", "htmx.min.js", "atlantis-icon.png", "favicon.png"} {
		resp, _ := get(t, srv, "/ui/static/"+name)
		Equals(t, http.StatusOK, resp.StatusCode)
	}
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func post(t *testing.T, srv *httptest.Server, path string, form url.Values, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	Ok(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := noRedirectClient().Do(req)
	Ok(t, err)
	resp.Body.Close()
	return resp
}

func TestDiscardLocks_UnlocksAndRecordsActor(t *testing.T) {
	actions := &fakeActions{missing: map[string]bool{"gone": true}}
	srv := newServer(t, sampleStore(), actions, "")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ui/locks/discard",
		strings.NewReader(url.Values{"id": {"a", "b", "gone"}, "return": {"/ui/locks"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("alice", "pw")
	resp, err := noRedirectClient().Do(req)
	Ok(t, err)
	resp.Body.Close()

	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/locks?done=unlocked&missing=1&n=2", resp.Header.Get("Location"))
	Equals(t, []string{"a", "b"}, actions.discarded)
	Equals(t, []string{"alice", "alice"}, actions.actors)

	_, body := get(t, srv, "/ui/locks?done=unlocked&missing=1&n=2")
	assertContains(t, body, "Unlocked 2 projects", "1 was already unlocked")
}

func TestDiscardLocks_NoneSelected(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, sampleStore(), actions, "")
	resp := post(t, srv, "/ui/locks/discard", url.Values{}, nil)
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/locks?done=none-selected", resp.Header.Get("Location"))
	Equals(t, 0, len(actions.discarded))
}

func TestDiscardLocks_Error(t *testing.T) {
	actions := &fakeActions{err: errors.New("redis down")}
	srv := newServer(t, sampleStore(), actions, "")
	resp := post(t, srv, "/ui/locks/discard", url.Values{"id": {"a"}}, nil)
	Equals(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestActions_RejectCrossOrigin(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, sampleStore(), actions, "")
	for _, path := range []string{"/ui/locks/discard", "/ui/applies/lock", "/ui/applies/unlock"} {
		resp := post(t, srv, path, url.Values{"id": {"a"}}, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
		Equals(t, http.StatusForbidden, resp.StatusCode)
	}
	Equals(t, 0, len(actions.discarded))
	Equals(t, 0, actions.locked)
	Equals(t, 0, actions.unlocked)
}

func TestActions_SameOriginAllowed(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, sampleStore(), actions, "")
	resp := post(t, srv, "/ui/applies/lock", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/locks?done=applies-locked", resp.Header.Get("Location"))
	resp = post(t, srv, "/ui/applies/unlock", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, 1, actions.locked)
	Equals(t, 1, actions.unlocked)
}

func TestActions_ReturnPathCannotLeaveTheUI(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	for _, ret := range []string{"https://evil.example/ui", "//evil.example/ui", "/\\evil.example", "/other", "/ui/../admin", "/uix", "/ui/locks#frag"} {
		resp := post(t, srv, "/ui/applies/lock", url.Values{"return": {ret}}, nil)
		Equals(t, "/ui/locks?done=applies-locked", resp.Header.Get("Location"))
	}
	resp := post(t, srv, "/ui/applies/lock", url.Values{"return": {"/ui/repos/acme/infra/pulls/1482"}}, nil)
	Equals(t, "/ui/repos/acme/infra/pulls/1482?done=applies-locked", resp.Header.Get("Location"))
	// Only the host parameter survives from the return path's query.
	resp = post(t, srv, "/ui/applies/lock", url.Values{"return": {"/ui/repos/acme/infra/pulls/1482?host=github.com&x=//evil"}}, nil)
	Equals(t, "/ui/repos/acme/infra/pulls/1482?host=github.com&done=applies-locked", resp.Header.Get("Location"))
}

func TestPages_PullLinksCarryHost(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	_, body := get(t, srv, "/ui/pulls")
	assertContains(t, body, `/ui/repos/acme/infra/pulls/1482?host=github.com`)
	resp, _ := get(t, srv, "/ui/repos/acme/infra/pulls/1482?host=gitlab.com")
	Equals(t, http.StatusNotFound, resp.StatusCode)
	resp, _ = get(t, srv, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	Equals(t, http.StatusOK, resp.StatusCode)
}

func TestFlash_UnknownKeyIgnored(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	_, body := get(t, srv, "/ui/locks?done=<b>pwned</b>")
	Assert(t, !strings.Contains(body, "pwned"), "unknown flash key rendered")
}

func readEvents(t *testing.T, srv *httptest.Server, path string, lastID string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	Ok(t, err)
	defer resp.Body.Close()
	Equals(t, "text/event-stream", resp.Header.Get("Content-Type"))
	var b strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		b.WriteString(sc.Text())
		b.WriteString("\n")
		if strings.HasPrefix(sc.Text(), "event: done") {
			// Keep the done event's data line, the job's final status.
			if sc.Scan() {
				b.WriteString(sc.Text())
				b.WriteString("\n")
			}
			break
		}
	}
	return b.String()
}

func TestJobEvents_StreamsAndResumes(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	body := readEvents(t, srv, "/ui/jobs/job-1/events", "")
	assertContains(t, body, "retry: 3000", "id: 1\ndata: $ terraform init\n", "id: 3\ndata: multi\ndata: line\n", "event: done")

	resumed := readEvents(t, srv, "/ui/jobs/job-1/events", "2")
	Assert(t, !strings.Contains(resumed, "id: 1\n"), "resumed stream repeated line 1")
	Assert(t, !strings.Contains(resumed, "id: 2\n"), "resumed stream repeated line 2")
	assertContains(t, resumed, "id: 3\n", "event: done")
}

func TestJobEvents_KeepAliveWhileIdle(t *testing.T) {
	store := sampleStore()
	live := make(chan webui.LogLine)
	store.liveLogs = map[string]chan webui.LogLine{"job-1": live}
	srv := newServer(t, store, &fakeActions{}, "")

	resp, err := http.Get(srv.URL + "/ui/jobs/job-1/events")
	Ok(t, err)
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sawKeepAlive := false
	for sc.Scan() {
		if sc.Text() == ": keep-alive" {
			sawKeepAlive = true
			break
		}
	}
	Assert(t, sawKeepAlive, "expected a keep-alive comment while the job is idle")
	close(live)
}

func TestJobEvents_UnknownJob(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	resp, _ := get(t, srv, "/ui/jobs/nope/events")
	Equals(t, http.StatusNotFound, resp.StatusCode)
}
