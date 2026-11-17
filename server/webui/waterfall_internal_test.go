// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/runatlantis/atlantis/testing"
)

var t0 = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

func span(id, parent string, startMS, endMS int) TraceSpan {
	return TraceSpan{ID: id, ParentID: parent, Name: id, Category: TraceStep,
		Start: t0.Add(time.Duration(startMS) * time.Millisecond), End: t0.Add(time.Duration(endMS) * time.Millisecond)}
}

func rowsByID(w waterfall) map[string]waterfallRow {
	out := map[string]waterfallRow{}
	for _, r := range w.Rows {
		out[r.Span.ID] = r
	}
	return out
}

func TestWaterfall_PositionsAndNesting(t *testing.T) {
	tr := JobTrace{Spans: []TraceSpan{
		// Out of order, as spans arrive.
		span("c2", "b", 3500, 9000),
		span("job", "", 0, 10000),
		span("a", "job", 0, 3000),
		span("b", "job", 3000, 10000),
		span("c1", "b", 3000, 5000),
		span("c3", "b", 4000, 4500),
	}}
	w := buildWaterfall(tr, t0.Add(time.Hour), defaultWaterfallLimits)
	Equals(t, 10*time.Second, w.Total)
	var order []string
	for _, r := range w.Rows {
		order = append(order, fmt.Sprintf("%s@%d", r.Span.ID, r.Depth))
	}
	Equals(t, []string{"job@0", "a@1", "b@1", "c1@2", "c2@2", "c3@2"}, order)

	rows := rowsByID(w)
	Equals(t, 0.0, rows["job"].Offset)
	Equals(t, 1000.0, rows["job"].Width)
	Equals(t, 350.0, rows["c2"].Offset)
	Equals(t, 550.0, rows["c2"].Width)
	Equals(t, "350.00", rows["c2"].barX())
	Equals(t, "550.00", rows["c2"].barWidth())
	Equals(t, 3500*time.Millisecond, rows["c2"].StartOffset)
	Assert(t, rows["b"].HasChildren && !rows["a"].HasChildren, "children flags wrong")

	// The job waited on a, then b; inside b on c2, and on c1 before it.
	for id, want := range map[string]bool{"job": true, "a": true, "b": true, "c1": true, "c2": true, "c3": false} {
		Equals(t, want, rows[id].Critical)
	}
	Equals(t, []string{"0s", "2.50s", "5.00s", "7.50s", "10.0s"}, w.Ticks)

	// The slowest list leaves out the job's own span.
	tr.Spans[1].Category = TraceJob
	w = buildWaterfall(tr, t0, defaultWaterfallLimits)
	Equals(t, "b", w.Slowest[0].Span.ID)
	Equals(t, "c3", w.Slowest[len(w.Slowest)-1].Span.ID)
	Equals(t, 5, len(w.Slowest))
}

func TestWaterfall_RunningSpansReachNow(t *testing.T) {
	job := span("job", "", 0, 0)
	job.End = time.Time{}
	tr := JobTrace{Spans: []TraceSpan{job, span("a", "job", 0, 1000)}}
	w := buildWaterfall(tr, t0.Add(4*time.Second), defaultWaterfallLimits)
	Assert(t, w.Running, "running trace not reported")
	Equals(t, 4*time.Second, w.Total)
	Equals(t, 250.0, rowsByID(w)["a"].Width)
}

func TestWaterfall_OrphansAndCyclesBecomeRoots(t *testing.T) {
	tr := JobTrace{Spans: []TraceSpan{
		span("job", "", 0, 1000),
		span("orphan", "gone", 100, 200),
		span("x", "y", 100, 200),
		span("y", "x", 100, 200),
	}}
	w := buildWaterfall(tr, t0, defaultWaterfallLimits)
	Equals(t, 4, len(w.Rows))
	Equals(t, 0, rowsByID(w)["orphan"].Depth)
}

func TestWaterfall_FoldsShortSpansWhenThereAreMany(t *testing.T) {
	spans := []TraceSpan{span("job", "", 0, 100000), span("slow", "job", 0, 90000)}
	for i := range 20 {
		spans = append(spans, span(fmt.Sprintf("tiny%02d", i), "job", 1000+i, 1001+i))
	}
	failed := span("tiny-failed", "job", 2000, 2001)
	failed.Error = true
	spans = append(spans, failed)
	lim := waterfallLimits{Fold: 10, Max: 100, Tiny: 0.005}
	w := buildWaterfall(JobTrace{Spans: spans}, t0, lim)
	// job, slow, one fold of 20, and the failed span, which is never folded.
	Equals(t, 4, len(w.Rows))
	Equals(t, 20, w.Folded)
	fold := w.Rows[2]
	Equals(t, "20 more spans", fold.Span.Name)
	Equals(t, 20, fold.More)
	Equals(t, 1, fold.Depth)
	Equals(t, 19*time.Millisecond+time.Millisecond, fold.Duration)
	Equals(t, "tiny-failed", w.Rows[3].Span.ID)

	// Below the fold limit every span gets a row.
	w = buildWaterfall(JobTrace{Spans: spans}, t0, defaultWaterfallLimits)
	Equals(t, len(spans), len(w.Rows))

	lim.Max = 2
	w = buildWaterfall(JobTrace{Spans: spans}, t0, lim)
	Equals(t, 2, len(w.Rows))
	Equals(t, 2, w.Truncated)
}

func TestWaterfall_Empty(t *testing.T) {
	w := buildWaterfall(JobTrace{}, t0, defaultWaterfallLimits)
	Equals(t, 0, len(w.Rows))
}

func TestFormatSpanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                                "0s",
		850 * time.Microsecond:           "850µs",
		12 * time.Millisecond:            "12ms",
		1400 * time.Millisecond:          "1.40s",
		42 * time.Second:                 "42.0s",
		2*time.Minute + 5*time.Second:    "2m05s",
		3*time.Hour + 4*time.Minute + 1:  "3h04m",
		-time.Second:                     "0s",
		999*time.Millisecond + 999999:    "999ms",
		10*time.Second - time.Nanosecond: "10.00s",
	} {
		Equals(t, want, formatSpanDuration(d))
	}
}

func TestWaterfallRow_TinyBarsStayVisibleAndInside(t *testing.T) {
	r := waterfallRow{Offset: 999.9, Width: 0}
	Equals(t, "999.00", r.barX())
	Equals(t, "1.00", r.barWidth())
	r = waterfallRow{Offset: 600, Width: 500}
	Equals(t, "400.00", r.barWidth())
}

func toolSpan(id, parent, source string, startMS, endMS int) TraceSpan {
	s := span(id, parent, startMS, endMS)
	s.Category, s.Source = TraceTool, source
	return s
}

func TestToolName_FollowsWhatReportedTheSpans(t *testing.T) {
	job := span("job", "", 0, 10)
	job.Source = atlantisSource
	for name, c := range map[string]struct {
		sources []string
		want    string
	}{
		"opentofu":  {[]string{"OpenTofu CLI", "OpenTofu CLI"}, "OpenTofu"},
		"terraform": {[]string{"Terraform CLI"}, "Terraform"},
		"both":      {[]string{"OpenTofu CLI", "Terraform CLI"}, "OpenTofu / Terraform"},
		"unknown":   {[]string{"my-wrapper"}, "OpenTofu / Terraform"},
		"none":      {nil, "OpenTofu / Terraform"},
	} {
		t.Run(name, func(t *testing.T) {
			spans := []TraceSpan{job}
			for i, src := range c.sources {
				spans = append(spans, toolSpan(fmt.Sprintf("s%d", i), "job", src, 1, 2))
			}
			Equals(t, c.want, toolName(spans))
			Equals(t, c.want, buildWaterfall(JobTrace{Spans: spans}, t0, defaultWaterfallLimits).Tool)
		})
	}
	Equals(t, "OpenTofu", categoryLabel(toolSpan("a", "", "OpenTofu CLI", 0, 1)))
	Equals(t, "Terraform", categoryLabel(toolSpan("a", "", "Terraform CLI", 0, 1)))
	Equals(t, "OpenTofu / Terraform", categoryLabel(toolSpan("a", "", "", 0, 1)))
	Equals(t, "Resource", categoryLabel(TraceSpan{Category: TraceResource, Source: "Terraform CLI"}))
	Equals(t, "Atlantis", reportedBy(atlantisSource))
	Equals(t, "OpenTofu", reportedBy("OpenTofu CLI"))
	Equals(t, "Terraform", reportedBy("Terraform CLI"))
	Equals(t, "my-wrapper", reportedBy("my-wrapper"))
}

// moduleTrace is tofu init installing a local module, which OpenTofu
// marks as an error with the given message, under a command that ended
// with cmdErr.
func moduleTrace(msg string, cmdErr bool) JobTrace {
	job := span("job", "", 0, 1000)
	job.Category = TraceJob
	cmd := span("cmd", "job", 0, 900)
	cmd.Category, cmd.Source, cmd.Error = TraceCommand, atlantisSource, cmdErr
	get := toolSpan("get", "cmd", "OpenTofu CLI", 10, 50)
	mod := toolSpan("mod", "get", "OpenTofu CLI", 20, 30)
	mod.Error, mod.Message = true, msg
	return JobTrace{Spans: []TraceSpan{job, cmd, get, mod}}
}

func TestWaterfall_BenignToolErrorsAreNotFailures(t *testing.T) {
	for name, c := range map[string]struct {
		msg    string
		cmdErr bool
		failed bool
	}{
		"no diagnostics, command ok":     {"no diagnostics", false, false},
		"no message, command ok":         {"", false, false},
		"no diagnostics, command failed": {"no diagnostics", true, true},
		"real message, command ok":       {"Module not found", false, true},
		"near miss message":              {"no diagnostics!", false, true},
	} {
		t.Run(name, func(t *testing.T) {
			w := buildWaterfall(moduleTrace(c.msg, c.cmdErr), t0, defaultWaterfallLimits)
			mod := rowsByID(w)["mod"]
			Equals(t, c.failed, mod.Failed)
			Equals(t, !c.failed, mod.Benign)
			// The raw status stays on the span.
			Assert(t, mod.Span.Error, "raw error status lost")
			want := 0
			if c.failed {
				want = 1
			}
			if c.cmdErr {
				want++
			}
			Equals(t, want, w.Errors)
			Equals(t, !c.failed, !strings.Contains(rowClasses(mod), "err"))
		})
	}

	// A running command has not succeeded yet.
	tr := moduleTrace("no diagnostics", false)
	tr.Spans[1].End = time.Time{}
	Assert(t, rowsByID(buildWaterfall(tr, t0.Add(time.Second), defaultWaterfallLimits))["mod"].Failed, "benign under a running command")

	// Without a command span the direct parent decides.
	tr = moduleTrace("no diagnostics", false)
	tr.Spans[2].ParentID = "job"
	tr.Spans = append(tr.Spans[:1], tr.Spans[2:]...)
	Assert(t, !rowsByID(buildWaterfall(tr, t0, defaultWaterfallLimits))["mod"].Failed, "benign under a parent that succeeded")
	tr.Spans[1].Error = true
	Assert(t, rowsByID(buildWaterfall(tr, t0, defaultWaterfallLimits))["mod"].Failed, "benign under a parent that failed")

	// Atlantis's own errors always count.
	tr = moduleTrace("", false)
	tr.Spans[3].Source = atlantisSource
	Assert(t, rowsByID(buildWaterfall(tr, t0, defaultWaterfallLimits))["mod"].Failed, "atlantis span error ignored")

	// An orphan or a span in a parent cycle has no parent that succeeded.
	tr = JobTrace{Spans: []TraceSpan{toolSpan("x", "y", "OpenTofu CLI", 0, 1), toolSpan("y", "x", "OpenTofu CLI", 0, 1)}}
	tr.Spans[0].Error, tr.Spans[1].Error = true, true
	Equals(t, 2, buildWaterfall(tr, t0, defaultWaterfallLimits).Errors)
}

func httpSpan(id, parent string, startMS, endMS int) TraceSpan {
	s := toolSpan(id, parent, "OpenTofu CLI", startMS, endMS)
	s.Name = "HTTP GET"
	s.Attributes = []TraceAttribute{{Key: "http.request.method", Value: "GET"}, {Key: "span.kind", Value: "client"}}
	return s
}

func TestIsHTTPSpan(t *testing.T) {
	Assert(t, isHTTPSpan(httpSpan("a", "", 0, 1)), "HTTP GET")
	named := toolSpan("a", "", "Terraform CLI", 0, 1)
	named.Name = "HTTP HEAD"
	Assert(t, isHTTPSpan(named), "name prefix")
	byAttrs := httpSpan("a", "", 0, 1)
	byAttrs.Name = "registry lookup"
	Assert(t, isHTTPSpan(byAttrs), "client span with a method")
	byAttrs.Attributes = byAttrs.Attributes[:1]
	Assert(t, !isHTTPSpan(byAttrs), "method without client kind")
	own := httpSpan("a", "", 0, 1)
	own.Source = atlantisSource
	Assert(t, !isHTTPSpan(own), "atlantis span")
	Assert(t, !isHTTPSpan(toolSpan("HTTPServer", "", "OpenTofu CLI", 0, 1)), "plain span")
}

func TestWaterfall_GroupsHTTPRequests(t *testing.T) {
	job := span("job", "", 0, 10000)
	job.Category = TraceJob
	spans := []TraceSpan{job, toolSpan("install", "job", "OpenTofu CLI", 0, 9000)}
	for i := range 12 {
		spans = append(spans, httpSpan(fmt.Sprintf("h%02d", i), "install", 10+i*100, 110+i*100))
	}
	// The last request is on the critical path; one failed. Requests that
	// run one after another are all on it.
	spans = append(spans, httpSpan("h-crit", "install", 5000, 9000))
	bad := httpSpan("h-bad", "install", 2000, 2100)
	bad.Error, bad.Message = true, "404 Not Found"
	spans = append(spans, bad)
	// A lone request elsewhere is not grouped.
	spans = append(spans, toolSpan("other", "job", "OpenTofu CLI", 9000, 9500), httpSpan("lone", "other", 9000, 9100))

	w := buildWaterfall(JobTrace{Spans: spans}, t0, defaultWaterfallLimits)
	var order []string
	for _, r := range w.Rows {
		order = append(order, fmt.Sprintf("%s@%d", r.Span.ID, r.Depth))
	}
	Equals(t, "job@0 install@1 http-install@2", strings.Join(order[:3], " "))
	g := w.Rows[2]
	Assert(t, g.HTTPGroup && g.HasChildren && g.Critical && !g.Failed, "group row flags")
	Equals(t, "13 HTTP requests", g.Span.Name)
	Equals(t, 5200*time.Millisecond, g.HTTPTotal)
	Equals(t, "13 HTTP requests · 5.20s total", groupLabel(g))
	Equals(t, 8990*time.Millisecond, g.Duration)
	for _, r := range w.Rows[3:16] {
		Equals(t, 3, r.Depth)
		Equals(t, "http-install", r.Group)
	}
	rows := rowsByID(w)
	// Requests on the critical path stay marked inside the group, so the
	// critical path view still lists them; failed requests stay outside.
	Assert(t, rows["h-crit"].Critical, "critical request lost its mark")
	Equals(t, "http-install", rows["h-crit"].Group)
	for _, id := range []string{"h-bad", "lone"} {
		Equals(t, "", rows[id].Group)
	}
	Equals(t, 2, rows["h-bad"].Depth)
	Assert(t, rows["h-bad"].Failed, "failed request")
	Equals(t, 15, w.HTTPRequests)
	Equals(t, len(spans)+1, len(w.Rows))

	// The slowest list leaves requests out unless asked.
	for _, r := range w.Slowest {
		Assert(t, !isHTTPSpan(r.Span), "%s in the slowest list", r.Span.ID)
	}
	Equals(t, []string{"install", "other"}, []string{w.Slowest[0].Span.ID, w.Slowest[1].Span.ID})
	Equals(t, 2, len(w.Slowest))
	Equals(t, 10, len(w.SlowestAll))
	Equals(t, "h-crit", w.SlowestAll[1].Span.ID)
}
