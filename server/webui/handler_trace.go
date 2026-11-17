// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// timingData is what the Timing view shows.
type timingData struct {
	Job   Job
	Trace JobTrace
	W     waterfall
}

// timing shows a job's timing trace as a waterfall. With partial=1 it
// renders only the waterfall, for live updates.
func (h *Handler) timing(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	jobsCrumb := crumb{Label: "Jobs", Href: h.BasePath + "/ui/jobs"}
	j, ok := h.Store.GetJob(r.Context(), id)
	if !ok {
		if r.URL.Query().Get("partial") == "1" {
			http.Error(w, "This replica has no record of that job.", http.StatusNotFound)
			return
		}
		m := h.meta(r, "Job not found", "jobs", jobsCrumb, crumb{Label: "Not found"})
		h.render(w, r, http.StatusNotFound, errorPage(m, "This replica has no record of that job",
			"Job output and timing traces live in memory on the replica that ran the job and are cleared on restart. Try reloading; a load balancer may route you to another replica."))
		return
	}
	t := h.Store.JobTrace(r.Context(), id)
	d := timingData{Job: j, Trace: t}
	if t.Status == TraceReady {
		d.W = buildWaterfall(t, h.now(), defaultWaterfallLimits)
	}
	if r.URL.Query().Get("partial") == "1" {
		w.Header().Set("Cache-Control", "no-store")
		h.render(w, r, http.StatusOK, timingBody(h.BasePath, d))
		return
	}
	jobCrumb := crumb{Label: jobLabel(j), Href: jobHref(h.BasePath, j.ID)}
	m := h.meta(r, "Timing of "+jobLabel(j), "jobs", jobsCrumb, jobCrumb, crumb{Label: "Timing"})
	h.render(w, r, http.StatusOK, timingPage(m, d))
}

// traceEvents tells a Timing view when the trace changes, so it reloads the
// waterfall. Each "trace" event carries the trace's version; a "done" event
// follows once the job and its trace have finished.
func (h *Handler) traceEvents(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, ok := h.Store.GetJob(r.Context(), id); !ok {
		http.Error(w, "This replica has no record of that job.", http.StatusNotFound)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-cache")
	hd.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s := &sseWriter{w: w, rc: http.NewResponseController(w), timeout: h.writeTimeout()}
	if s.write("retry: 3000\n\n") != nil || s.flush() != nil {
		return
	}
	last, _ := strconv.ParseUint(r.Header.Get("Last-Event-ID"), 10, 64)
	poll := time.NewTicker(h.tracePoll())
	defer poll.Stop()
	beat := time.NewTicker(h.heartbeat())
	defer beat.Stop()
	for {
		t := h.Store.JobTrace(ctx, id)
		j, ok := h.Store.GetJob(ctx, id)
		if t.Status == TraceReady && t.Version != last {
			last = t.Version
			if s.write("event: trace\nid: "+strconv.FormatUint(last, 10)+"\ndata: "+strconv.FormatUint(last, 10)+"\n\n") != nil || s.flush() != nil {
				return
			}
		}
		if !ok || t.Status != TraceReady || (t.Finished && !j.Running()) {
			_ = s.write("event: done\ndata: \n\n")
			_ = s.flush()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-beat.C:
			if s.write(": keep-alive\n\n") != nil || s.flush() != nil {
				return
			}
		case <-poll.C:
		}
	}
}

func (h *Handler) tracePoll() time.Duration {
	if h.TracePollInterval > 0 {
		return h.TracePollInterval
	}
	return time.Second
}
