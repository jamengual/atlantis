// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

// Package jobtrace records timing traces of Atlantis jobs. Atlantis records a
// span for each job and each of its steps, and passes the trace context to
// the Terraform or OpenTofu processes it starts, so that their OpenTelemetry
// spans join the same trace. A local OTLP/HTTP receiver collects those spans.
//
// Traces live in memory on the replica that ran the job, next to the job's
// output, and are removed with it.
package jobtrace

import (
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"time"
)

// Category groups spans for display.
type Category string

const (
	// CategoryJob is the span covering a whole Atlantis job.
	CategoryJob Category = "job"
	// CategoryStep is an Atlantis step, such as clone, init, plan, or a run
	// step.
	CategoryStep Category = "step"
	// CategoryCommand is one Terraform or OpenTofu process Atlantis started.
	CategoryCommand Category = "command"
	// CategoryTool is a span Terraform or OpenTofu reported that is about
	// neither a provider nor a resource.
	CategoryTool Category = "tool"
	// CategoryProvider is a provider install, configuration, or validation.
	CategoryProvider Category = "provider"
	// CategoryResource is work on one resource, such as planning or applying
	// it.
	CategoryResource Category = "resource"
)

// Defaults for a Recorder.
const (
	DefaultMaxSpans  = 20000
	DefaultMaxTraces = 2000
	// acceptAfterEnd is how long spans are still accepted after the job's
	// span ended. Processes flush their spans before they exit, so this only
	// covers spans that are in flight when the job ends.
	acceptAfterEnd = time.Minute
	maxNotes       = 8
)

// Attribute is a span attribute. Hidden attributes keep their key but not
// their value, because the value may be sensitive.
type Attribute struct {
	Key    string
	Value  string
	Hidden bool
}

// Span is a recorded span.
type Span struct {
	ID       string
	ParentID string
	Name     string
	Category Category
	// Source is "atlantis" for Atlantis's own spans, or the reporting
	// service's name, such as "OpenTofu CLI".
	Source string
	Start  time.Time
	// End is zero while the span is open.
	End     time.Time
	Error   bool
	Message string
	// Attributes are sorted by key.
	Attributes []Attribute
}

// Trace is a snapshot of a job's trace.
type Trace struct {
	JobID   string
	TraceID string
	Spans   []Span
	// Dropped counts spans that arrived after the trace reached its span
	// limit.
	Dropped int
	// Notes explain gaps, such as a workflow that sends its spans elsewhere.
	Notes []string
	// Finished is true once the job's span ended.
	Finished bool
	// AllAttributes is true when attribute values outside the allowlist are
	// kept.
	AllAttributes bool
	// Version changes whenever the trace changes.
	Version uint64
}

// Recorder keeps the traces of the jobs on this replica. A nil *Recorder
// records nothing, so callers don't need to check whether tracing is on.
type Recorder struct {
	// MaxSpans bounds the spans kept per trace. Defaults to DefaultMaxSpans.
	MaxSpans int
	// MaxTraces bounds the traces kept. When there are more, the oldest
	// finished traces are removed. Defaults to DefaultMaxTraces.
	MaxTraces int
	// AllAttributes keeps every attribute value. By default only the values
	// of allowlisted attributes are kept.
	AllAttributes bool
	// Now returns the current time. Tests replace it.
	Now func() time.Time

	mu       sync.Mutex
	endpoint string
	traces   map[string]*trace
	byID     map[[16]byte]*trace
	order    []string
}

type trace struct {
	jobID    string
	id       [16]byte
	spans    []Span
	index    map[string]int
	open     []string
	dropped  int
	notes    []string
	root     string
	finished time.Time
	version  uint64
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Recorder) maxSpans() int {
	if r.MaxSpans > 0 {
		return r.MaxSpans
	}
	return DefaultMaxSpans
}

func (r *Recorder) maxTraces() int {
	if r.MaxTraces > 0 {
		return r.MaxTraces
	}
	return DefaultMaxTraces
}

// SetEndpoint sets the base URL of the OTLP/HTTP receiver that processes
// send spans to. Until it is set, processes get no trace context.
func (r *Recorder) SetEndpoint(url string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.endpoint = url
	r.mu.Unlock()
}

func (r *Recorder) lazyInit() {
	if r.traces == nil {
		r.traces = map[string]*trace{}
		r.byID = map[[16]byte]*trace{}
	}
}

// ActiveSpan is a span Atlantis started and has not ended yet. A nil
// *ActiveSpan does nothing.
type ActiveSpan struct {
	r     *Recorder
	t     *trace
	id    string
	ended bool
}

// Start begins a span in the job's trace, creating the trace if the job has
// none yet. The span's parent is the innermost span of the job that is still
// open, so steps nest under the job and commands under steps. Steps of one
// job run one after another, which this relies on.
func (r *Recorder) Start(jobID, name string, cat Category, attrs ...Attribute) *ActiveSpan {
	if r == nil || jobID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lazyInit()
	t := r.traces[jobID]
	if t == nil {
		t = &trace{jobID: jobID, index: map[string]int{}}
		_, _ = rand.Read(t.id[:])
		r.traces[jobID] = t
		r.byID[t.id] = t
		r.order = append(r.order, jobID)
		r.evictLocked()
	}
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	parent := ""
	if n := len(t.open); n > 0 {
		parent = t.open[n-1]
	} else if t.root != "" && t.finished.IsZero() {
		parent = t.root
	}
	s := Span{ID: id, ParentID: parent, Name: name, Category: cat, Source: "atlantis", Start: r.now()}
	s.Attributes = append(s.Attributes, attrs...)
	slices.SortStableFunc(s.Attributes, func(a, b Attribute) int { return strings.Compare(a.Key, b.Key) })
	if !r.addLocked(t, s) {
		return nil
	}
	if t.root == "" {
		t.root = id
		t.finished = time.Time{}
	}
	t.open = append(t.open, id)
	return &ActiveSpan{r: r, t: t, id: id}
}

// addLocked stores a span unless the trace is full. It returns whether the
// span was stored.
func (r *Recorder) addLocked(t *trace, s Span) bool {
	if i, ok := t.index[s.ID]; ok {
		t.spans[i] = s
		t.version++
		return true
	}
	if len(t.spans) >= r.maxSpans() {
		t.dropped++
		t.version++
		return false
	}
	t.index[s.ID] = len(t.spans)
	t.spans = append(t.spans, s)
	t.version++
	return true
}

// evictLocked removes the oldest finished traces while there are too many.
func (r *Recorder) evictLocked() {
	for len(r.order) > r.maxTraces() {
		victim := -1
		for i, id := range r.order {
			if t := r.traces[id]; t != nil && !t.finished.IsZero() {
				victim = i
				break
			}
		}
		if victim < 0 {
			return
		}
		r.removeLocked(r.order[victim])
	}
}

func (r *Recorder) removeLocked(jobID string) {
	t := r.traces[jobID]
	if t == nil {
		return
	}
	delete(r.traces, jobID)
	delete(r.byID, t.id)
	r.order = slices.DeleteFunc(r.order, func(id string) bool { return id == jobID })
}

// End ends the span. A non-nil err marks it failed with err's message.
// Ending the job's first span finishes the trace.
func (s *ActiveSpan) End(err error) {
	if s == nil {
		return
	}
	r := s.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	t := s.t
	t.open = slices.DeleteFunc(t.open, func(id string) bool { return id == s.id })
	i, ok := t.index[s.id]
	if !ok {
		return
	}
	now := r.now()
	sp := &t.spans[i]
	sp.End = now
	if err != nil {
		sp.Error = true
		sp.Message = truncate(err.Error(), maxValueLen)
	}
	if s.id == t.root {
		t.finished = now
	}
	t.version++
}

// ID is the span's hex ID.
func (s *ActiveSpan) ID() string {
	if s == nil {
		return ""
	}
	return s.id
}

// otelEnvPrefix marks the OpenTelemetry SDK's environment variables.
const otelEnvPrefix = "OTEL_"

// Env returns the environment variables that make a Terraform or OpenTofu
// process export its spans to Atlantis as children of this span. environ is
// the environment the process would get otherwise. When it already sets
// OpenTelemetry variables, the workflow sends spans elsewhere: Env returns
// nothing and notes it on the trace.
func (s *ActiveSpan) Env(environ []string) []string {
	if s == nil {
		return nil
	}
	r := s.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.endpoint == "" {
		return nil
	}
	for _, kv := range environ {
		if strings.HasPrefix(kv, otelEnvPrefix) {
			key, _, _ := strings.Cut(kv, "=")
			s.t.noteLocked("The workflow or server sets " + key + ", so its commands send traces to the collector it configures instead of to Atlantis. Only Atlantis steps are shown.")
			return nil
		}
	}
	return []string{
		"OTEL_TRACES_EXPORTER=otlp",
		"OTEL_EXPORTER_OTLP_ENDPOINT=" + r.endpoint,
		"OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
		"TRACEPARENT=00-" + hex.EncodeToString(s.t.id[:]) + "-" + s.id + "-01",
	}
}

// Env is ActiveSpan.Env for the job's innermost open span, such as the run
// step that starts the process. It returns nothing when the job has no open
// span.
func (r *Recorder) Env(jobID string, environ []string) []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	t := r.traces[jobID]
	var s *ActiveSpan
	if t != nil && len(t.open) > 0 {
		s = &ActiveSpan{r: r, t: t, id: t.open[len(t.open)-1]}
	}
	r.mu.Unlock()
	return s.Env(environ)
}

func (t *trace) noteLocked(note string) {
	if slices.Contains(t.notes, note) || len(t.notes) >= maxNotes {
		return
	}
	t.notes = append(t.notes, note)
	t.version++
}

// Snapshot returns a copy of the job's trace.
func (r *Recorder) Snapshot(jobID string) (Trace, bool) {
	if r == nil {
		return Trace{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.traces[jobID]
	if t == nil {
		return Trace{}, false
	}
	out := Trace{
		JobID:         t.jobID,
		TraceID:       hex.EncodeToString(t.id[:]),
		Spans:         make([]Span, len(t.spans)),
		Dropped:       t.dropped,
		Notes:         slices.Clone(t.notes),
		Finished:      !t.finished.IsZero(),
		AllAttributes: r.AllAttributes,
		Version:       t.version,
	}
	for i, s := range t.spans {
		s.Attributes = slices.Clone(s.Attributes)
		out.Spans[i] = s
	}
	return out, true
}

// Forget removes the traces of the jobs, as when their pull request's job
// output is cleaned up.
func (r *Recorder) Forget(jobIDs ...string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range jobIDs {
		r.removeLocked(id)
	}
}

// accepting returns the trace with the ID if it still takes spans.
func (r *Recorder) acceptingLocked(id [16]byte) *trace {
	t := r.byID[id]
	if t == nil {
		return nil
	}
	if !t.finished.IsZero() && r.now().Sub(t.finished) > acceptAfterEnd {
		return nil
	}
	return t
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n] + "…"
}
