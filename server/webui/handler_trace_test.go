// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/jobtrace"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

// sampleTrace is a finished plan: the job, init and plan steps, a tofu
// command, a provider install and two resources, one of which failed.
func sampleTrace() webui.JobTrace {
	at := func(ms int) time.Time { return now.Add(-time.Minute).Add(time.Duration(ms) * time.Millisecond) }
	return webui.JobTrace{
		TraceID: "0af7651916cd43dd8448eb211c80319c", Finished: true, Version: 7,
		Spans: []webui.TraceSpan{
			{ID: "j", Name: "atlantis plan", Category: webui.TraceJob, Source: "atlantis", Start: at(0), End: at(10000)},
			{ID: "s1", ParentID: "j", Name: "init", Category: webui.TraceStep, Source: "atlantis", Start: at(100), End: at(3000)},
			{ID: "p1", ParentID: "s1", Name: `Install Provider "registry.opentofu.org/hashicorp/null"`, Category: webui.TraceProvider, Source: "OpenTofu CLI", Start: at(200), End: at(2500),
				Attributes: []webui.TraceAttribute{{Key: "opentofu.provider.address", Value: "registry.opentofu.org/hashicorp/null"}, {Key: "url.full", Hidden: true}}},
			{ID: "s2", ParentID: "j", Name: "plan", Category: webui.TraceStep, Source: "atlantis", Start: at(3000), End: at(9900)},
			{ID: "c2", ParentID: "s2", Name: "tofu plan", Category: webui.TraceCommand, Source: "atlantis", Start: at(3010), End: at(9800)},
			{ID: "r1", ParentID: "c2", Name: "Plan resource instance changes", Category: webui.TraceResource, Source: "OpenTofu CLI", Start: at(4000), End: at(9000),
				Attributes: []webui.TraceAttribute{{Key: "opentofu.resource_instance.address", Value: "time_sleep.warmup"}}},
			{ID: "r2", ParentID: "c2", Name: "Plan resource instance changes", Category: webui.TraceResource, Source: "OpenTofu CLI", Start: at(4000), End: at(4500),
				Error: true, Message: "provider crashed",
				Attributes: []webui.TraceAttribute{{Key: "opentofu.resource_instance.address", Value: "null_resource.app[0]"}}},
		},
	}
}

func traceStore() *fakeStore {
	s := stopStore()
	s.caps = webui.Capabilities{Traces: true}
	s.traces = map[string]webui.JobTrace{"infra-plan": sampleTrace()}
	return s
}

func TestTiming_ShowsTheWaterfall(t *testing.T) {
	s := traceStore()
	s.jobs[0].Done = true
	srv := newServer(t, s, &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/jobs/infra-plan/timing")
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, body,
		`aria-current="page">Timing</a>`,
		`data-src="/ui/jobs/infra-plan/timing?partial=1"`,
		`data-id="r1"`, `data-depth="3"`,
		// The job takes the whole axis; the 5s resource starts 4s in.
		`<rect x="0.00" y="2" width="1000.00" height="10">`,
		`<rect x="400.00" y="2" width="500.00" height="10">`,
		"time_sleep.warmup", "provider crashed",
		"1 attribute values hidden", "url.full", "--web-traces-all-attributes",
		"Slowest spans", "10.0s", "Timing traces live in memory on the replica",
	)
	// The failed resource and the long one on the critical path are marked.
	assertContains(t, body, `class="wf-row d3 cat-resource err"`, `class="wf-row d3 cat-resource crit"`)
	// The finished trace needs no live updates.
	Assert(t, !strings.Contains(body, "data-events="), "finished trace streams updates")

	// A running job's trace updates live.
	s.jobs[0].Done = false
	_, body = get(t, srv, "/ui/jobs/infra-plan/timing")
	assertContains(t, body, `data-events="/ui/jobs/infra-plan/timing/events"`)

	_, out := get(t, srv, "/ui/jobs/infra-plan")
	assertContains(t, out, `href="/ui/jobs/infra-plan/timing"`, `aria-current="page">Output</a>`)
}

func TestTiming_PartialRendersOnlyTheWaterfall(t *testing.T) {
	srv := newServer(t, traceStore(), &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/jobs/infra-plan/timing?partial=1")
	Equals(t, http.StatusOK, resp.StatusCode)
	Assert(t, !strings.Contains(body, "<html"), "partial rendered the layout")
	assertContains(t, body, `data-id="j"`)
	resp, _ = get(t, srv, "/ui/jobs/nope/timing?partial=1")
	Equals(t, http.StatusNotFound, resp.StatusCode)
}

func TestTiming_ExplainsMissingTraces(t *testing.T) {
	s := traceStore()
	s.traces = map[string]webui.JobTrace{}
	srv := newServer(t, s, &fakeActions{}, "")
	_, body := get(t, srv, "/ui/jobs/infra-plan/timing")
	assertContains(t, body, "This replica has no timing trace for this job.")

	off := stopStore()
	srv = newServer(t, off, &fakeActions{}, "")
	_, body = get(t, srv, "/ui/jobs/infra-plan/timing")
	assertContains(t, body, "Timing traces are off on this server.")
	_, out := get(t, srv, "/ui/jobs/infra-plan")
	Assert(t, !strings.Contains(out, "/timing"), "job page links to timing with tracing off")

	resp, _ := get(t, srv, "/ui/jobs/nope/timing")
	Equals(t, http.StatusNotFound, resp.StatusCode)
}

func TestTiming_EscapesSpanNamesAndAttributes(t *testing.T) {
	s := traceStore()
	tr := sampleTrace()
	tr.Spans[5].Name = `<script>alert("name")</script>`
	tr.Spans[5].Message = `<img src=x onerror=alert(1)>`
	tr.Spans[5].Attributes = []webui.TraceAttribute{{Key: `<b>key</b>`, Value: `"><svg onload=alert(2)>`}}
	s.traces["infra-plan"] = tr
	srv := newServer(t, s, &fakeActions{}, "")
	for _, path := range []string{"/ui/jobs/infra-plan/timing", "/ui/jobs/infra-plan/timing?partial=1"} {
		_, body := get(t, srv, path)
		for _, raw := range []string{`<script>alert`, `<img src=x`, `<svg onload`, `<b>key`} {
			Assert(t, !strings.Contains(body, raw), "%s rendered %q unescaped", path, raw)
		}
		assertContains(t, body, "&lt;script&gt;alert(&#34;name&#34;)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;")
	}
	_, _, raw := getJSON(t, http.DefaultClient, srv.URL+"/ui/api/v1/jobs/infra-plan/trace")
	Assert(t, !strings.Contains(raw, "<script>"), "API returned raw markup: %s", raw)
}

func TestTiming_ViewersCanSeeIt(t *testing.T) {
	srv, idp := newSignInServer(t, traceStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, map[string]any{"sub": "v", "name": "Vera Viewer", "email": "vera@acme.com", "email_verified": true})
	status, body := b.get(t, "/ui/jobs/infra-plan/timing")
	Equals(t, http.StatusOK, status)
	assertContains(t, body, "time_sleep.warmup")
	status, _ = b.get(t, "/ui/api/v1/jobs/infra-plan/trace")
	Equals(t, http.StatusOK, status)

	// Signed-out visitors get nothing.
	resp, err := http.Get(srv.URL + "/ui/api/v1/jobs/infra-plan/trace")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusUnauthorized, resp.StatusCode)
	anon := newBrowser(t, srv.URL)
	resp, err = anon.noFollow().Get(srv.URL + "/ui/jobs/infra-plan/timing")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)

}

func TestAPI_JobTrace(t *testing.T) {
	s := traceStore()
	tr := sampleTrace()
	tr.Spans[0].End = time.Time{}
	tr.Finished = false
	s.traces["infra-plan"] = tr
	srv := newServer(t, s, &fakeActions{}, "")
	resp, body, raw := getJSON(t, http.DefaultClient, srv.URL+"/ui/api/v1/jobs/infra-plan/trace")
	Equals(t, http.StatusOK, resp.StatusCode)
	item := body.(map[string]any)["item"].(map[string]any)
	Equals(t, "ready", item["status"])
	Equals(t, "0af7651916cd43dd8448eb211c80319c", item["trace_id"])
	spans := item["spans"].([]any)
	Equals(t, 7, len(spans))
	job := spans[0].(map[string]any)
	Equals(t, nil, job["end"])
	Equals(t, nil, job["duration_ms"])
	p1 := spans[2].(map[string]any)
	Equals(t, 2300.0, p1["duration_ms"])
	attrs := p1["attributes"].([]any)
	Equals(t, map[string]any{"key": "url.full", "value": nil, "hidden": true}, attrs[1])
	Assert(t, strings.Contains(raw, `"capabilities":{`), "no capabilities: %s", raw)
	Equals(t, true, body.(map[string]any)["capabilities"].(map[string]any)["traces"])

	off := newServer(t, stopStore(), &fakeActions{}, "")
	_, body, _ = getJSON(t, http.DefaultClient, off.URL+"/ui/api/v1/jobs/infra-plan/trace")
	Equals(t, "off", body.(map[string]any)["item"].(map[string]any)["status"])
	resp, _, _ = getJSON(t, http.DefaultClient, off.URL+"/ui/api/v1/jobs/nope/trace")
	Equals(t, http.StatusNotFound, resp.StatusCode)
}

// liveTraceStore changes its trace when the test says so.
type liveTraceStore struct {
	*fakeStore
	versions chan webui.JobTrace
	current  webui.JobTrace
}

func (l *liveTraceStore) JobTrace(context.Context, string) webui.JobTrace {
	select {
	case t := <-l.versions:
		l.current = t
	default:
	}
	return l.current
}

func TestTimingEvents_StreamsChangesUntilDone(t *testing.T) {
	base := traceStore()
	base.jobs[0].Done = false
	running := sampleTrace()
	running.Status, running.Finished, running.Version = webui.TraceReady, false, 1
	store := &liveTraceStore{fakeStore: base, versions: make(chan webui.JobTrace, 2), current: running}
	h := &webui.Handler{Store: store, Actions: &fakeActions{}, Logger: logging.NewNoopLogger(t), Now: func() time.Time { return now },
		HeartbeatInterval: time.Second, TracePollInterval: 10 * time.Millisecond}
	r := mux.NewRouter()
	h.Register(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/ui/jobs/infra-plan/timing/events")
	Ok(t, err)
	defer resp.Body.Close()
	Equals(t, "text/event-stream", resp.Header.Get("Content-Type"))
	sc := bufio.NewScanner(resp.Body)
	next := func() string {
		for sc.Scan() {
			if ev, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				return ev
			}
		}
		return ""
	}
	Equals(t, "trace", next())
	update := running
	update.Version = 2
	store.versions <- update
	Equals(t, "trace", next())
	finished := update
	finished.Version, finished.Finished = 3, true
	base.jobs[0].Done = true
	store.versions <- finished
	Equals(t, "trace", next())
	Equals(t, "done", next())
}

// ---------- the legacy store ----------

func TestLegacyStore_JobTraceMergesProcessRootSpans(t *testing.T) {
	rec := jobtrace.NewRecorder()
	job := rec.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	cmd := rec.Start("job-1", "tofu plan", jobtrace.CategoryCommand)
	cmd.End(errors.New("exit status 1"))
	job.End(nil)

	store := &webui.LegacyStore{Jobs: &fakeJobSource{}, Traces: fakeTraceSource{rec: rec, extra: []jobtrace.Span{
		{ID: "root", ParentID: cmd.ID(), Name: "tofu", Source: "OpenTofu CLI", Category: jobtrace.CategoryTool, Error: true, Message: "plan failed"},
		{ID: "phase", ParentID: "root", Name: "Plan phase", Source: "OpenTofu CLI", Category: jobtrace.CategoryTool},
	}}}
	tr := store.JobTrace(context.Background(), "job-1")
	Equals(t, webui.TraceReady, tr.Status)
	Equals(t, 3, len(tr.Spans))
	Equals(t, "Plan phase", tr.Spans[2].Name)
	Equals(t, cmd.ID(), tr.Spans[2].ParentID)
	Equals(t, "exit status 1", tr.Spans[1].Message)

	Equals(t, webui.TraceMissing, store.JobTrace(context.Background(), "other").Status)
	Assert(t, store.Capabilities().Traces, "capabilities don't report traces")
	Equals(t, webui.TraceOff, (&webui.LegacyStore{}).JobTrace(context.Background(), "job-1").Status)
	Assert(t, !(&webui.LegacyStore{}).Capabilities().Traces, "traces reported without a source")
}

type fakeTraceSource struct {
	rec   *jobtrace.Recorder
	extra []jobtrace.Span
}

func (f fakeTraceSource) Snapshot(id string) (jobtrace.Trace, bool) {
	t, ok := f.rec.Snapshot(id)
	t.Spans = append(t.Spans, f.extra...)
	return t, ok
}

type fakeJobSource struct{}

func (fakeJobSource) GetPullToJobMapping() []jobs.PullInfoWithJobIDs { return nil }
func (fakeJobSource) Register(string, chan string)                   {}
func (fakeJobSource) Deregister(string, chan string)                 {}
