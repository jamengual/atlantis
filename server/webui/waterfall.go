// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Waterfall bar positions are in SVG user units across this width.
const waterfallWidth = 1000

// waterfallLimits bound the rows a waterfall renders.
type waterfallLimits struct {
	// Fold is the row count above which short leaf spans are folded into
	// "N more spans" rows.
	Fold int
	// Max is the most rows rendered; the rest are counted.
	Max int
	// Tiny is the share of the trace below which a leaf span counts as
	// short.
	Tiny float64
}

var defaultWaterfallLimits = waterfallLimits{Fold: 300, Max: 1500, Tiny: 0.005}

// waterfall is a trace laid out for display.
type waterfall struct {
	Start time.Time
	Total time.Duration
	Rows  []waterfallRow
	// Ticks label the time axis at 0, 25, 50, 75 and 100 percent.
	Ticks []string
	// Folded counts spans shown only as part of an "N more spans" row.
	Folded int
	// Truncated counts rows left out because there were too many.
	Truncated int
	// Slowest are the ten longest spans, not counting the job's own or
	// HTTP requests.
	Slowest []waterfallRow
	// SlowestAll are the ten longest spans including HTTP requests.
	SlowestAll []waterfallRow
	// HTTPRequests counts HTTP request spans with no children.
	HTTPRequests int
	// Errors counts failed spans. Spans a tool reported as errors without
	// saying why, under a command that succeeded, don't count.
	Errors int
	// Tool names the tool that reported spans: OpenTofu, Terraform, or
	// "OpenTofu / Terraform" when both did or it is not known.
	Tool string
	// Running is true while a span is still open.
	Running bool
	// Spans is how many spans the trace has.
	Spans int
}

// waterfallRow is one row: a span, or a fold of several short spans.
type waterfallRow struct {
	Span  TraceSpan
	Depth int
	// Offset and Width position the bar in SVG units.
	Offset, Width float64
	Duration      time.Duration
	// StartOffset is how long after the trace's start the span began.
	StartOffset time.Duration
	Critical    bool
	HasChildren bool
	// More is the number of spans a fold row stands for; zero for a span.
	More int
	// Index is the row's position in tree order.
	Index int
	// Failed is true when the span failed. A span the tool reported as an
	// error with no message, under a command that succeeded, has not.
	Failed bool
	// Benign is true when the tool reported the span as an error but it is
	// not counted as failed.
	Benign bool
	// HTTPGroup is true for a row that stands for the HTTP requests below
	// it; HTTPTotal is their summed duration.
	HTTPGroup bool
	HTTPTotal time.Duration
	// Group is the ID of the HTTP group row a request row belongs to.
	Group string
}

// Fold reports whether the row stands for several spans.
func (r waterfallRow) Fold() bool { return r.More > 0 }

type spanNode struct {
	span     TraceSpan
	start    time.Time
	end      time.Time
	children []*spanNode
	critical bool
	// benign is true when the span's reported error is not counted.
	benign bool
}

func (n *spanNode) failed() bool { return n.span.Error && !n.benign }

// httpLeaf reports whether the span is an HTTP request with no spans below
// it.
func (n *spanNode) httpLeaf() bool { return len(n.children) == 0 && isHTTPSpan(n.span) }

func (n *spanNode) dur() time.Duration { return n.end.Sub(n.start) }

// buildWaterfall lays out a trace. Running spans extend to now.
func buildWaterfall(t JobTrace, now time.Time, lim waterfallLimits) waterfall {
	w := waterfall{Spans: len(t.Spans)}
	if len(t.Spans) == 0 {
		return w
	}
	nodes := make(map[string]*spanNode, len(t.Spans))
	ordered := make([]*spanNode, 0, len(t.Spans))
	for _, s := range t.Spans {
		if _, dup := nodes[s.ID]; dup {
			continue
		}
		n := &spanNode{span: s, start: s.Start, end: s.End}
		if s.Running() {
			w.Running = true
			n.end = now
		}
		if n.end.Before(n.start) {
			n.end = n.start
		}
		nodes[s.ID] = n
		ordered = append(ordered, n)
	}
	for _, n := range ordered {
		n.benign = benignError(n, nodes)
		if n.failed() {
			w.Errors++
		}
	}
	w.Tool = toolName(t.Spans)
	var roots []*spanNode
	for _, n := range ordered {
		if p, ok := nodes[n.span.ParentID]; ok && p != n && !ancestorOf(n, p, nodes) {
			p.children = append(p.children, n)
		} else {
			roots = append(roots, n)
		}
	}
	byStart := func(a, b *spanNode) int {
		if c := a.start.Compare(b.start); c != 0 {
			return c
		}
		return cmp.Compare(a.span.ID, b.span.ID)
	}
	slices.SortStableFunc(roots, byStart)
	for _, n := range ordered {
		slices.SortStableFunc(n.children, byStart)
	}

	w.Start = ordered[0].start
	end := ordered[0].end
	for _, n := range ordered {
		if n.start.Before(w.Start) {
			w.Start = n.start
		}
		if n.end.After(end) {
			end = n.end
		}
	}
	w.Total = max(end.Sub(w.Start), time.Millisecond)
	for i := 0; i <= 4; i++ {
		w.Ticks = append(w.Ticks, formatSpanDuration(w.Total*time.Duration(i)/4))
	}

	// The critical path runs through the longest root, normally the job.
	longest := roots[0]
	for _, r := range roots {
		if r.dur() > longest.dur() {
			longest = r
		}
	}
	markCritical(longest, longest.end)

	fold := len(ordered) > lim.Fold
	tiny := time.Duration(float64(w.Total) * lim.Tiny)
	var emit func(n *spanNode, depth int)
	emit = func(n *spanNode, depth int) {
		w.Rows = append(w.Rows, w.nodeRow(n, depth))
		// HTTP requests are grouped under one row, unless they failed.
		// Requests on the critical path stay in the group, which is marked
		// critical; the critical path view lists them on their own.
		var http []*spanNode
		for _, c := range n.children {
			if c.httpLeaf() && !c.failed() {
				http = append(http, c)
			}
		}
		if len(http) < 2 {
			http = nil
		}
		var pending []*spanNode
		flush := func() {
			switch len(pending) {
			case 0:
			case 1:
				emit(pending[0], depth+1)
			default:
				first, last := pending[0].start, pending[0].end
				for _, p := range pending {
					first = minTime(first, p.start)
					last = maxTime(last, p.end)
				}
				label := TraceSpan{ID: "more-" + pending[0].span.ID, ParentID: n.span.ID, Name: fmt.Sprintf("%d more spans", len(pending)), Category: pending[0].span.Category, Source: pending[0].span.Source}
				w.Rows = append(w.Rows, w.row(label, first, last, depth+1, false, false, len(pending)))
				w.Folded += len(pending)
			}
			pending = nil
		}
		for _, c := range n.children {
			if len(http) > 0 && slices.Contains(http, c) {
				if c == http[0] {
					flush()
					w.emitHTTPGroup(n, http, depth+1)
				}
				continue
			}
			if fold && len(c.children) == 0 && !c.critical && !c.failed() && c.dur() < tiny {
				pending = append(pending, c)
				continue
			}
			flush()
			emit(c, depth+1)
		}
		flush()
	}
	for _, r := range roots {
		emit(r, 0)
	}
	if len(w.Rows) > lim.Max {
		w.Truncated = len(w.Rows) - lim.Max
		w.Rows = w.Rows[:lim.Max]
	}
	for i := range w.Rows {
		w.Rows[i].Index = i
	}

	var all, noHTTP []waterfallRow
	for _, n := range ordered {
		if n.span.Category == TraceJob {
			continue
		}
		r := w.nodeRow(n, 0)
		all = append(all, r)
		if n.httpLeaf() {
			w.HTTPRequests++
		} else {
			noHTTP = append(noHTTP, r)
		}
	}
	slowest := func(a, b waterfallRow) int { return cmp.Compare(b.Duration, a.Duration) }
	slices.SortStableFunc(all, slowest)
	slices.SortStableFunc(noHTTP, slowest)
	w.SlowestAll = all[:min(10, len(all))]
	w.Slowest = noHTTP[:min(10, len(noHTTP))]
	return w
}

// emitHTTPGroup adds a row standing for HTTP requests, followed by a row
// for each request one level deeper.
func (w *waterfall) emitHTTPGroup(parent *spanNode, reqs []*spanNode, depth int) {
	first, last := reqs[0].start, reqs[0].end
	var total time.Duration
	critical := false
	for _, r := range reqs {
		first = minTime(first, r.start)
		last = maxTime(last, r.end)
		total += r.dur()
		critical = critical || r.critical
	}
	id := "http-" + parent.span.ID
	label := TraceSpan{ID: id, ParentID: parent.span.ID, Name: fmt.Sprintf("%d HTTP requests", len(reqs)),
		Category: TraceTool, Source: reqs[0].span.Source}
	g := w.row(label, first, last, depth, true, critical, 0)
	g.HTTPGroup, g.HTTPTotal = true, total
	w.Rows = append(w.Rows, g)
	for _, r := range reqs {
		row := w.nodeRow(r, depth+1)
		row.Group = id
		w.Rows = append(w.Rows, row)
	}
}

func (w waterfall) nodeRow(n *spanNode, depth int) waterfallRow {
	r := w.row(n.span, n.start, n.end, depth, len(n.children) > 0, n.critical, 0)
	r.Failed, r.Benign = n.failed(), n.benign
	return r
}

// benignMessage is the status message OpenTofu gives spans it marks as
// errors without any error, such as installing a local module.
const benignMessage = "no diagnostics"

// benignError reports whether a span a tool marked as an error did not
// fail: the tool gave no reason, or only benignMessage, and the command it
// ran under (or, without one, its parent) finished without an error.
func benignError(n *spanNode, nodes map[string]*spanNode) bool {
	s := n.span
	if !s.Error || s.Source == "" || s.Source == atlantisSource || (s.Message != "" && s.Message != benignMessage) {
		return false
	}
	parent := nodes[s.ParentID]
	seen := map[*spanNode]bool{n: true}
	for cur := parent; cur != nil && !seen[cur]; cur = nodes[cur.span.ParentID] {
		seen[cur] = true
		if cur.span.Category == TraceCommand {
			parent = cur
			break
		}
	}
	return parent != nil && parent != n && !parent.span.Error && !parent.span.Running()
}

// isHTTPSpan reports whether a span is an HTTP request a tool made, such
// as a registry lookup or a provider download.
func isHTTPSpan(s TraceSpan) bool {
	if s.Source == atlantisSource {
		return false
	}
	if strings.HasPrefix(s.Name, "HTTP ") {
		return true
	}
	var client, method bool
	for _, a := range s.Attributes {
		switch a.Key {
		case "span.kind":
			client = a.Value == "client"
		case "http.request.method":
			method = true
		}
	}
	return client && method
}

// ancestorOf reports whether n is an ancestor of p, which would make a
// cycle if p became n's parent.
func ancestorOf(n, p *spanNode, nodes map[string]*spanNode) bool {
	seen := map[*spanNode]bool{}
	for cur := p; cur != nil && !seen[cur]; {
		if cur == n {
			return true
		}
		seen[cur] = true
		cur = nodes[cur.span.ParentID]
	}
	return false
}

// markCritical marks the spans the job waited on: working back from the
// span's end, the child that finished last before that time, then the child
// that finished last before that child started, and so on.
func markCritical(n *spanNode, until time.Time) {
	n.critical = true
	children := slices.Clone(n.children)
	slices.SortStableFunc(children, func(a, b *spanNode) int { return b.end.Compare(a.end) })
	t := minTime(n.end, until)
	for _, c := range children {
		if !c.start.Before(t) {
			continue
		}
		markCritical(c, minTime(c.end, t))
		t = c.start
		if !t.After(n.start) {
			break
		}
	}
}

func (w waterfall) row(s TraceSpan, start, end time.Time, depth int, children, critical bool, more int) waterfallRow {
	total := float64(w.Total)
	off := float64(start.Sub(w.Start)) / total * waterfallWidth
	width := float64(end.Sub(start)) / total * waterfallWidth
	return waterfallRow{
		Span: s, Depth: depth, Offset: off, Width: width, Duration: end.Sub(start),
		StartOffset: start.Sub(w.Start), Critical: critical, HasChildren: children, More: more,
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// formatSpanDuration renders a duration compactly: 850µs, 12ms, 1.4s,
// 2m05s.
func formatSpanDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d < time.Millisecond:
		return strconv.FormatInt(d.Microseconds(), 10) + "µs"
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	case d < 10*time.Second:
		return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + "s"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

// barX and barWidth format bar positions for SVG attributes. A bar is at
// least one unit wide so instant spans stay visible.
func (r waterfallRow) barX() string {
	return strconv.FormatFloat(min(r.Offset, waterfallWidth-1), 'f', 2, 64)
}

func (r waterfallRow) barWidth() string {
	return strconv.FormatFloat(min(max(r.Width, 1), waterfallWidth-min(r.Offset, waterfallWidth-1)), 'f', 2, 64)
}

// atlantisSource is the Source of spans Atlantis records itself.
const atlantisSource = "atlantis"

const (
	toolOpenTofu  = "OpenTofu"
	toolTerraform = "Terraform"
	toolEither    = "OpenTofu / Terraform"
)

// sourceTool names the tool behind a span's reported service name, such as
// "OpenTofu CLI", or "" when it is neither OpenTofu nor Terraform.
func sourceTool(source string) string {
	s := strings.ToLower(source)
	switch {
	case strings.Contains(s, "opentofu") || strings.Contains(s, "tofu"):
		return toolOpenTofu
	case strings.Contains(s, "terraform"):
		return toolTerraform
	}
	return ""
}

// toolName names the tool that reported a trace's spans.
func toolName(spans []TraceSpan) string {
	found := ""
	for _, s := range spans {
		if s.Source == atlantisSource || s.Source == "" {
			continue
		}
		t := sourceTool(s.Source)
		if t == "" || (found != "" && found != t) {
			return toolEither
		}
		found = t
	}
	if found == "" {
		return toolEither
	}
	return found
}

// reportedBy names what reported a span, for people.
func reportedBy(source string) string {
	if source == atlantisSource {
		return "Atlantis"
	}
	if t := sourceTool(source); t != "" {
		return t
	}
	return source
}

// categoryLabel names a span's category for people. Spans of the tool
// category are named after the tool that reported them.
func categoryLabel(s TraceSpan) string {
	switch s.Category {
	case TraceJob:
		return "Atlantis job"
	case TraceStep:
		return "Atlantis step"
	case TraceCommand:
		return "Command"
	case TraceProvider:
		return "Provider"
	case TraceResource:
		return "Resource"
	}
	if t := sourceTool(s.Source); t != "" {
		return t
	}
	return toolEither
}

// categoryClass is the CSS class that colors a span's bar.
func categoryClass(c TraceCategory) string {
	switch c {
	case TraceJob, TraceStep:
		return "cat-atlantis"
	case TraceCommand, TraceTool:
		return "cat-tool"
	case TraceProvider:
		return "cat-provider"
	case TraceResource:
		return "cat-resource"
	}
	return "cat-tool"
}

// depthClass indents a row. Deeper rows share the last indent.
func depthClass(d int) string {
	return "d" + strconv.Itoa(min(d, 12))
}
