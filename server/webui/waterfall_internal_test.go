// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"fmt"
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
