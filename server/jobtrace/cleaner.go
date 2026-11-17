// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package jobtrace

import "github.com/runatlantis/atlantis/server/jobs"

// JobOutput is the part of the job output handler that OutputCleaner wraps.
type JobOutput interface {
	CleanUp(pullInfo jobs.PullInfo)
	GetPullToJobMapping() []jobs.PullInfoWithJobIDs
}

// OutputCleaner removes a pull request's job traces together with its job
// output, so traces live exactly as long as the output they describe.
type OutputCleaner struct {
	Output   JobOutput
	Recorder *Recorder
}

// CleanUp removes the job output and traces of a pull request's project.
func (c OutputCleaner) CleanUp(pullInfo jobs.PullInfo) {
	var ids []string
	for _, m := range c.Output.GetPullToJobMapping() {
		if m.Pull != pullInfo {
			continue
		}
		for _, info := range m.JobIDInfos {
			ids = append(ids, info.JobID)
		}
	}
	c.Output.CleanUp(pullInfo)
	c.Recorder.Forget(ids...)
}
