// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package jobtrace_test

import (
	"testing"

	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/jobtrace"
	. "github.com/runatlantis/atlantis/testing"
)

type fakeOutput struct {
	mapping []jobs.PullInfoWithJobIDs
	cleaned []jobs.PullInfo
}

func (f *fakeOutput) CleanUp(p jobs.PullInfo) { f.cleaned = append(f.cleaned, p) }
func (f *fakeOutput) GetPullToJobMapping() []jobs.PullInfoWithJobIDs {
	return f.mapping
}

func TestOutputCleaner_RemovesTracesWithTheirOutput(t *testing.T) {
	r := jobtrace.NewRecorder()
	r.Start("closed-1", "atlantis plan", jobtrace.CategoryJob).End(nil)
	r.Start("closed-2", "atlantis apply", jobtrace.CategoryJob).End(nil)
	r.Start("open", "atlantis plan", jobtrace.CategoryJob).End(nil)
	closed := jobs.PullInfo{PullNum: 1, RepoFullName: "acme/infra", Path: "network", Workspace: "default"}
	out := &fakeOutput{mapping: []jobs.PullInfoWithJobIDs{
		{Pull: closed, JobIDInfos: []jobs.JobIDInfo{{JobID: "closed-1"}, {JobID: "closed-2"}}},
		{Pull: jobs.PullInfo{PullNum: 2, RepoFullName: "acme/infra"}, JobIDInfos: []jobs.JobIDInfo{{JobID: "open"}}},
	}}
	jobtrace.OutputCleaner{Output: out, Recorder: r}.CleanUp(closed)
	Equals(t, []jobs.PullInfo{closed}, out.cleaned)
	for id, want := range map[string]bool{"closed-1": false, "closed-2": false, "open": true} {
		_, ok := r.Snapshot(id)
		Equals(t, want, ok)
	}
}
