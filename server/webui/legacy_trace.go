// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"context"

	"github.com/runatlantis/atlantis/server/jobtrace"
)

// TraceSource holds job timing traces. *jobtrace.Recorder implements it.
type TraceSource interface {
	Snapshot(jobID string) (jobtrace.Trace, bool)
}

// JobTrace reads a job's trace from this replica's memory.
func (s *LegacyStore) JobTrace(_ context.Context, id string) JobTrace {
	if s.Traces == nil {
		return JobTrace{Status: TraceOff}
	}
	t, ok := s.Traces.Snapshot(id)
	if !ok {
		return JobTrace{Status: TraceMissing}
	}
	return toJobTrace(t)
}

// isProcessRoot reports whether a span is the root span a Terraform or
// OpenTofu process reports under the command span Atlantis started for it.
// Both cover the same process, so the UI shows only Atlantis's.
func isProcessRoot(s jobtrace.Span, parent jobtrace.Span) bool {
	return s.Source != "atlantis" && parent.Source == "atlantis" && parent.Category == jobtrace.CategoryCommand
}

func toJobTrace(t jobtrace.Trace) JobTrace {
	out := JobTrace{
		Status:        TraceReady,
		TraceID:       t.TraceID,
		Dropped:       t.Dropped,
		Notes:         t.Notes,
		Finished:      t.Finished,
		AllAttributes: t.AllAttributes,
		Version:       t.Version,
	}
	byID := make(map[string]jobtrace.Span, len(t.Spans))
	for _, s := range t.Spans {
		byID[s.ID] = s
	}
	// Spans whose parent is a process root move up to the command span.
	replace := map[string]string{}
	failed := map[string]string{}
	for _, s := range t.Spans {
		if p, ok := byID[s.ParentID]; ok && isProcessRoot(s, p) {
			replace[s.ID] = p.ID
			if s.Error {
				failed[p.ID] = s.Message
			}
		}
	}
	out.Spans = make([]TraceSpan, 0, len(t.Spans))
	for _, s := range t.Spans {
		if _, skip := replace[s.ID]; skip {
			continue
		}
		parent := s.ParentID
		if up, ok := replace[parent]; ok {
			parent = up
		}
		ts := TraceSpan{
			ID: s.ID, ParentID: parent, Name: s.Name, Category: TraceCategory(s.Category), Source: s.Source,
			Start: s.Start, End: s.End, Error: s.Error, Message: s.Message,
		}
		if msg, ok := failed[s.ID]; ok && !ts.Error {
			ts.Error, ts.Message = true, msg
		}
		for _, a := range s.Attributes {
			ts.Attributes = append(ts.Attributes, TraceAttribute(a))
		}
		out.Spans = append(out.Spans, ts)
	}
	return out
}
