// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package jobtrace_test

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/jobtrace"
	. "github.com/runatlantis/atlantis/testing"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newRecorder() (*jobtrace.Recorder, *clock) {
	c := &clock{t: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	r := jobtrace.NewRecorder()
	r.Now = c.now
	r.SetEndpoint("http://127.0.0.1:4318")
	return r, c
}

func TestRecorder_NestsStepsUnderTheJob(t *testing.T) {
	r, c := newRecorder()
	job := r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	c.t = c.t.Add(time.Second)
	step := r.Start("job-1", "init", jobtrace.CategoryStep)
	cmd := r.Start("job-1", "tofu init", jobtrace.CategoryCommand)
	c.t = c.t.Add(2 * time.Second)
	cmd.End(nil)
	step.End(errors.New("init failed"))
	plan := r.Start("job-1", "plan", jobtrace.CategoryStep)
	plan.End(nil)

	tr, ok := r.Snapshot("job-1")
	Assert(t, ok, "trace missing")
	Equals(t, 4, len(tr.Spans))
	Equals(t, "", tr.Spans[0].ParentID)
	Equals(t, job.ID(), tr.Spans[1].ParentID)
	Equals(t, step.ID(), tr.Spans[2].ParentID)
	Equals(t, job.ID(), tr.Spans[3].ParentID)
	Equals(t, 2*time.Second, tr.Spans[2].End.Sub(tr.Spans[2].Start))
	Assert(t, tr.Spans[1].Error, "step should be failed")
	Equals(t, "init failed", tr.Spans[1].Message)
	Assert(t, !tr.Finished, "trace finished before the job span ended")

	job.End(nil)
	job.End(errors.New("ignored"))
	tr, _ = r.Snapshot("job-1")
	Assert(t, tr.Finished, "trace not finished")
	Assert(t, !tr.Spans[0].Error, "second End changed the span")
}

func TestRecorder_NilIsSafe(t *testing.T) {
	var r *jobtrace.Recorder
	s := r.Start("job", "x", jobtrace.CategoryStep)
	s.End(nil)
	Equals(t, 0, len(s.Env(nil)))
	_, ok := r.Snapshot("job")
	Assert(t, !ok, "nil recorder has traces")
	r.Forget("job")
	r.SetEndpoint("x")
}

func TestActiveSpan_EnvPointsProcessesAtTheSpan(t *testing.T) {
	r, _ := newRecorder()
	job := r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	cmd := r.Start("job-1", "tofu plan", jobtrace.CategoryCommand)
	env := cmd.Env([]string{"PATH=/bin", "TRACEPARENT_NOT=1"})
	tr, _ := r.Snapshot("job-1")
	Equals(t, []string{
		"OTEL_TRACES_EXPORTER=otlp",
		"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318",
		"OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
		"TRACEPARENT=00-" + tr.TraceID + "-" + cmd.ID() + "-01",
	}, env)
	Assert(t, job.ID() != cmd.ID(), "span IDs repeat")
	Equals(t, 32, len(tr.TraceID))
}

func TestActiveSpan_EnvRespectsWorkflowOTELSettings(t *testing.T) {
	r, _ := newRecorder()
	r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	cmd := r.Start("job-1", "tofu plan", jobtrace.CategoryCommand)
	Equals(t, 0, len(cmd.Env([]string{"PATH=/bin", "OTEL_EXPORTER_OTLP_ENDPOINT=https://collector:4318"})))
	cmd.Env([]string{"OTEL_EXPORTER_OTLP_ENDPOINT=https://collector:4318"})
	tr, _ := r.Snapshot("job-1")
	Equals(t, 1, len(tr.Notes))
	Assert(t, strings.Contains(tr.Notes[0], "OTEL_EXPORTER_OTLP_ENDPOINT"), "note doesn't name the variable: %s", tr.Notes[0])
	Assert(t, !strings.Contains(tr.Notes[0], "collector:4318"), "note leaks the value")
}

func TestActiveSpan_EnvNeedsAReceiver(t *testing.T) {
	r := jobtrace.NewRecorder()
	cmd := r.Start("job-1", "tofu plan", jobtrace.CategoryCommand)
	Equals(t, 0, len(cmd.Env(nil)))
}

func TestRecorder_EvictsOldestFinishedTraces(t *testing.T) {
	r, _ := newRecorder()
	r.MaxTraces = 2
	r.Start("running", "a", jobtrace.CategoryJob)
	r.Start("done", "b", jobtrace.CategoryJob).End(nil)
	r.Start("new", "c", jobtrace.CategoryJob)
	_, ok := r.Snapshot("done")
	Assert(t, !ok, "finished trace kept")
	_, ok = r.Snapshot("running")
	Assert(t, ok, "running trace evicted")
	r.Forget("running")
	_, ok = r.Snapshot("running")
	Assert(t, !ok, "forgotten trace kept")
}

// ---------- receiver ----------

func traceIDOf(t *testing.T, r *jobtrace.Recorder, job string) []byte {
	tr, ok := r.Snapshot(job)
	Assert(t, ok, "no trace for %s", job)
	b, err := hex.DecodeString(tr.TraceID)
	Ok(t, err)
	return b
}

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func pbSpan(traceID []byte, id byte, parent []byte, name string, attrs ...*commonpb.KeyValue) *tracepb.Span {
	return &tracepb.Span{
		TraceId: traceID, SpanId: []byte{0, 0, 0, 0, 0, 0, 0, id}, ParentSpanId: parent, Name: name,
		Kind:              tracepb.Span_SPAN_KIND_INTERNAL,
		StartTimeUnixNano: uint64(time.Date(2026, 11, 16, 10, 0, 1, 0, time.UTC).UnixNano()),
		EndTimeUnixNano:   uint64(time.Date(2026, 11, 16, 10, 0, 3, 0, time.UTC).UnixNano()),
		Attributes:        attrs,
	}
}

func export(spans ...*tracepb.Span) []byte {
	b, _ := proto.Marshal(&tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", "OpenTofu CLI"), str("process.command_args", "tofu plan -var password=hunter2")}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: spans}},
	}}})
	return b
}

func post(t *testing.T, h http.Handler, ct string, body []byte, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestReceiver_AcceptsProtobufSpansOfLiveJobs(t *testing.T) {
	r, _ := newRecorder()
	cmd := r.Start("job-1", "tofu plan", jobtrace.CategoryCommand)
	tid := traceIDOf(t, r, "job-1")
	parent, _ := hex.DecodeString(cmd.ID())
	h := &jobtrace.Receiver{Recorder: r}

	w := post(t, h, "application/x-protobuf", export(
		pbSpan(tid, 1, parent, "tofu"),
		pbSpan(tid, 2, []byte{0, 0, 0, 0, 0, 0, 0, 1}, "Plan resource instance changes",
			str("opentofu.resource_instance.address", "aws_instance.web[0]"),
			str("url.full", "https://example.com/dl?sig=SECRET")),
		pbSpan(make([]byte, 16), 3, nil, "not ours"),
	))
	Equals(t, http.StatusOK, w.Code)
	// A partial success names the rejected span count.
	Assert(t, w.Body.Len() > 0, "no partial success for the rejected span")
	Assert(t, bytes.Contains(w.Body.Bytes(), []byte("no running Atlantis job")), "partial success message missing")

	tr, _ := r.Snapshot("job-1")
	Equals(t, 3, len(tr.Spans))
	phase, res := tr.Spans[1], tr.Spans[2]
	Equals(t, "tofu", phase.Name)
	Equals(t, cmd.ID(), phase.ParentID)
	Equals(t, "OpenTofu CLI", phase.Source)
	Equals(t, jobtrace.CategoryTool, phase.Category)
	Equals(t, jobtrace.CategoryResource, res.Category)
	Equals(t, 2*time.Second, res.End.Sub(res.Start))
	Equals(t, []jobtrace.Attribute{
		{Key: "opentofu.resource_instance.address", Value: "aws_instance.web[0]"},
		{Key: "span.kind", Value: "internal"},
		{Key: "url.full", Hidden: true},
	}, res.Attributes)
	for _, s := range tr.Spans {
		for _, a := range s.Attributes {
			Assert(t, !strings.Contains(a.Value, "hunter2") && !strings.Contains(a.Value, "SECRET"), "kept a sensitive value: %+v", a)
		}
	}
}

func TestReceiver_KeepsEveryValueWhenAllowed(t *testing.T) {
	r, _ := newRecorder()
	r.AllAttributes = true
	r.Start("job-1", "tofu plan", jobtrace.CategoryCommand)
	tid := traceIDOf(t, r, "job-1")
	post(t, &jobtrace.Receiver{Recorder: r}, "application/x-protobuf", export(pbSpan(tid, 1, nil, "HTTP GET", str("url.full", "https://example.com/a"))))
	tr, _ := r.Snapshot("job-1")
	Equals(t, jobtrace.Attribute{Key: "url.full", Value: "https://example.com/a"}, tr.Spans[1].Attributes[1])
	Assert(t, tr.AllAttributes, "snapshot doesn't say values are kept")
}

func TestReceiver_AcceptsJSON(t *testing.T) {
	r, _ := newRecorder()
	r.Start("job-1", "tofu apply", jobtrace.CategoryCommand)
	tid := hex.EncodeToString(traceIDOf(t, r, "job-1"))
	body := fmt.Sprintf(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"OpenTofu CLI"}}]},
	 "scopeSpans":[{"spans":[
	  {"traceId":%q,"spanId":"00000000000000a1","name":"Apply resource instance changes","kind":1,
	   "startTimeUnixNano":"1794823201000000000","endTimeUnixNano":1794823202500000000,
	   "attributes":[{"key":"opentofu.resource_instance.address","value":{"stringValue":"null_resource.app[0]"}},
	                 {"key":"http.response.status_code","value":{"intValue":"200"}},
	                 {"key":"opentofu.plan.target_addrs","value":{"arrayValue":{"values":[{"stringValue":"a"},{"boolValue":true}]}}}],
	   "status":{"code":2,"message":"boom"}},
	  {"traceId":"ffffffffffffffffffffffffffffffff","spanId":"00000000000000a2","name":"stranger"}]}]}]}`, tid)
	w := post(t, &jobtrace.Receiver{Recorder: r}, "application/json; charset=utf-8", []byte(body))
	Equals(t, http.StatusOK, w.Code)
	Assert(t, strings.Contains(w.Body.String(), `"rejectedSpans":"1"`), "body: %s", w.Body.String())
	tr, _ := r.Snapshot("job-1")
	Equals(t, 2, len(tr.Spans))
	s := tr.Spans[1]
	Equals(t, "00000000000000a1", s.ID)
	Assert(t, s.Error, "error status lost")
	Equals(t, "boom", s.Message)
	Equals(t, 1500*time.Millisecond, s.End.Sub(s.Start))
	Equals(t, []jobtrace.Attribute{
		{Key: "http.response.status_code", Value: "200"},
		{Key: "opentofu.plan.target_addrs", Hidden: true},
		{Key: "opentofu.resource_instance.address", Value: "null_resource.app[0]"},
		{Key: "span.kind", Value: "internal"},
	}, s.Attributes)
}

func TestReceiver_RejectsSpansAfterTheJob(t *testing.T) {
	r, c := newRecorder()
	r.Start("job-1", "atlantis plan", jobtrace.CategoryJob).End(nil)
	tid := traceIDOf(t, r, "job-1")
	h := &jobtrace.Receiver{Recorder: r}
	post(t, h, "application/x-protobuf", export(pbSpan(tid, 1, nil, "late but in time")))
	c.t = c.t.Add(2 * time.Minute)
	post(t, h, "application/x-protobuf", export(pbSpan(tid, 2, nil, "too late")))
	tr, _ := r.Snapshot("job-1")
	Equals(t, 2, len(tr.Spans))
	Equals(t, "late but in time", tr.Spans[1].Name)

	r.Forget("job-1")
	w := post(t, h, "application/x-protobuf", export(pbSpan(tid, 3, nil, "forgotten")))
	Equals(t, http.StatusOK, w.Code)
	_, ok := r.Snapshot("job-1")
	Assert(t, !ok, "forgotten trace came back")
}

func TestReceiver_CannotReplaceAtlantisSpans(t *testing.T) {
	r, _ := newRecorder()
	job := r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	tid := traceIDOf(t, r, "job-1")
	id, _ := hex.DecodeString(job.ID())
	sp := pbSpan(tid, 0, nil, "spoofed")
	sp.SpanId = id
	post(t, &jobtrace.Receiver{Recorder: r}, "application/x-protobuf", export(sp))
	tr, _ := r.Snapshot("job-1")
	Equals(t, "atlantis plan", tr.Spans[0].Name)
}

func TestReceiver_CapsSpansPerJob(t *testing.T) {
	r, _ := newRecorder()
	r.MaxSpans = 3
	r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	tid := traceIDOf(t, r, "job-1")
	var spans []*tracepb.Span
	for i := 1; i <= 5; i++ {
		spans = append(spans, pbSpan(tid, byte(i), nil, fmt.Sprintf("s%d", i)))
	}
	w := post(t, &jobtrace.Receiver{Recorder: r}, "application/x-protobuf", export(spans...))
	Equals(t, http.StatusOK, w.Code)
	tr, _ := r.Snapshot("job-1")
	Equals(t, 3, len(tr.Spans))
	Equals(t, 3, tr.Dropped)
}

func TestReceiver_RejectsBadRequests(t *testing.T) {
	r, _ := newRecorder()
	h := &jobtrace.Receiver{Recorder: r, MaxBodyBytes: 64}
	big := bytes.Repeat([]byte{'x'}, 65)
	Equals(t, http.StatusRequestEntityTooLarge, post(t, h, "application/x-protobuf", big).Code)
	Equals(t, http.StatusUnsupportedMediaType, post(t, h, "text/plain", []byte("x")).Code)
	Equals(t, http.StatusBadRequest, post(t, h, "application/json", []byte("{")).Code)
	Equals(t, http.StatusBadRequest, post(t, h, "application/x-protobuf", []byte{0xff, 0xff}).Code)
	Equals(t, http.StatusUnsupportedMediaType, post(t, h, "application/json", []byte("{}"), "Content-Encoding", "br").Code)

	// A small gzip body that inflates past the limit.
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write(bytes.Repeat([]byte(" "), 1000))
	_ = zw.Close()
	Assert(t, zb.Len() <= 64, "test body too large: %d", zb.Len())
	Equals(t, http.StatusRequestEntityTooLarge, post(t, h, "application/json", zb.Bytes(), "Content-Encoding", "gzip").Code)

	req := httptest.NewRequest(http.MethodGet, "/v1/traces", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	Equals(t, http.StatusMethodNotAllowed, w.Code)
	req = httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	Equals(t, http.StatusNotFound, w.Code)
}

func TestReceiver_AcceptsGzip(t *testing.T) {
	r, _ := newRecorder()
	r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	tid := traceIDOf(t, r, "job-1")
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write(export(pbSpan(tid, 1, nil, "zipped")))
	_ = zw.Close()
	Equals(t, http.StatusOK, post(t, &jobtrace.Receiver{Recorder: r}, "application/x-protobuf", zb.Bytes(), "Content-Encoding", "gzip").Code)
	tr, _ := r.Snapshot("job-1")
	Equals(t, 2, len(tr.Spans))
}

func TestListen_ServesOnLoopback(t *testing.T) {
	r := jobtrace.NewRecorder()
	srv, err := jobtrace.Listen(r, nil)
	Ok(t, err)
	defer srv.Close(t.Context()) //nolint:errcheck
	Assert(t, strings.HasPrefix(srv.Addr(), "127.0.0.1:"), "not on loopback: %s", srv.Addr())
	job := r.Start("job-1", "atlantis plan", jobtrace.CategoryJob)
	env := job.Env(nil)
	Equals(t, "OTEL_EXPORTER_OTLP_ENDPOINT=http://"+srv.Addr(), env[1])
	tid := traceIDOf(t, r, "job-1")
	resp, err := http.Post("http://"+srv.Addr()+"/v1/traces", "application/x-protobuf", bytes.NewReader(export(pbSpan(tid, 9, nil, "over the wire"))))
	Ok(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	Equals(t, http.StatusOK, resp.StatusCode)
	tr, _ := r.Snapshot("job-1")
	Equals(t, 2, len(tr.Spans))
}

func TestReceiver_StripsArgumentsFromProcessRootNames(t *testing.T) {
	r, _ := newRecorder()
	step := r.Start("job-1", "run: terraform", jobtrace.CategoryStep)
	tid := traceIDOf(t, r, "job-1")
	parent, _ := hex.DecodeString(step.ID())
	post(t, &jobtrace.Receiver{Recorder: r}, "application/x-protobuf", export(
		pbSpan(tid, 1, parent, `terraform plan -input\=false -var password=hunter2 -out /tmp/p`),
		pbSpan(tid, 2, parent, "terraform workspace select prod"),
		pbSpan(tid, 3, parent, "--version"),
		pbSpan(tid, 4, []byte{0, 0, 0, 0, 0, 0, 0, 1}, "install providers"),
	))
	tr, _ := r.Snapshot("job-1")
	var names []string
	for _, s := range tr.Spans[1:] {
		names = append(names, s.Name)
	}
	Equals(t, []string{"terraform plan", "terraform workspace select", "process", "install providers"}, names)
}
