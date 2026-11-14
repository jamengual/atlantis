// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

// Package webui serves the experimental Atlantis web UI.
//
// Pages read through the Store interface, whose records follow the data model
// in ADR 0005 (repository, pull request, project, job). Today the store is
// backed by the lock database, pull status, and in-memory job output. When
// durable storage lands, a second Store implementation can serve the same
// pages with history that survives restarts and spans replicas.
package webui

import (
	"context"
	"time"
)

// ProjectState is where a project is in the plan and apply cycle.
type ProjectState string

const (
	StateRunning      ProjectState = "running"
	StatePlanned      ProjectState = "planned"
	StateNoChanges    ProjectState = "no_changes"
	StateApplied      ProjectState = "applied"
	StatePlanFailed   ProjectState = "plan_failed"
	StateApplyFailed  ProjectState = "apply_failed"
	StateDiscarded    ProjectState = "discarded"
	StatePolicyFailed ProjectState = "policy_failed"
	StatePolicyPassed ProjectState = "policy_passed"
)

// Repository identifies a repository on a VCS host.
type Repository struct {
	VCSHost  string
	FullName string
}

// Changes counts the resource changes in a plan. Known is false when the
// plan output is not available, for example after a restart.
type Changes struct {
	Known   bool
	Import  int
	Add     int
	Change  int
	Destroy int
	Forget  int
}

// Total is the number of resources the plan touches.
func (c Changes) Total() int {
	return c.Import + c.Add + c.Change + c.Destroy + c.Forget
}

// Project is a Terraform project inside a pull request.
type Project struct {
	Dir       string
	Workspace string
	Name      string
	State     ProjectState
	Changes   Changes
	LockID    string
	// LatestJobID is the newest job this replica has output for, if any.
	LatestJobID string
}

// PullRequest is a pull request Atlantis has run commands for.
type PullRequest struct {
	Repo       Repository
	Num        int
	URL        string
	Author     string
	HeadBranch string
	BaseBranch string
	HeadCommit string
	Projects   []Project
	// LastActivity is the newest lock or job time this replica knows about.
	LastActivity time.Time
}

// Changes sums the known plan changes across projects.
func (p PullRequest) Changes() Changes {
	var c Changes
	for _, proj := range p.Projects {
		if !proj.Changes.Known {
			continue
		}
		c.Known = true
		c.Import += proj.Changes.Import
		c.Add += proj.Changes.Add
		c.Change += proj.Changes.Change
		c.Destroy += proj.Changes.Destroy
		c.Forget += proj.Changes.Forget
	}
	return c
}

// Lock is a project lock held by a pull request.
type Lock struct {
	ID          string
	Repo        Repository
	Dir         string
	Workspace   string
	ProjectName string
	PullNum     int
	PullURL     string
	PullAuthor  string
	User        string
	Since       time.Time
	// PullTracked is false when Atlantis has no status for the pull request,
	// which usually means it was closed while the lock survived.
	PullTracked bool
}

// ApplyLock is the global apply lock.
type ApplyLock struct {
	Locked bool
	// Enabled is false when the server disables the global apply lock.
	Enabled bool
	Since   time.Time
}

// Job is one command run for a project, such as a plan or an apply. Jobs from
// the in-memory output handler carry no VCS host, so they are matched to pull
// requests by repository name only.
type Job struct {
	ID          string
	Repo        Repository
	PullNum     int
	Dir         string
	Workspace   string
	ProjectName string
	Step        string
	Description string
	Done        bool
	// Stalled is true when an unfinished job has produced no output for a
	// long time, which usually means its process died.
	Stalled    bool
	LastOutput time.Time
	Lines      int
}

// JobFilter narrows ListJobs.
type JobFilter struct {
	RepoFullName string
	PullNum      int
	RunningOnly  bool
}

// Instance describes the replica serving the request.
type Instance struct {
	Version        string
	ShuttingDown   bool
	InProgressOps  int
	DatabaseOK     bool
	DatabaseError  string
	LockingBackend string
	StartedAt      time.Time
	Experiments    []string
}

// Capabilities says which data the store can answer. Pages hide or explain
// the panels a store cannot fill instead of showing incomplete data.
type Capabilities struct {
	// RunHistory is true when job records and logs survive restarts.
	RunHistory bool
	// ClusterJobs is true when jobs from every replica are visible.
	ClusterJobs bool
	// AuditLog is true when user actions are stored and can be listed.
	AuditLog bool
}

// Store is the read side of the web UI.
type Store interface {
	Capabilities() Capabilities
	Instance(ctx context.Context) Instance
	ListPulls(ctx context.Context) ([]PullRequest, error)
	// GetPull returns nil when Atlantis has no status for the pull request.
	// An empty repo.VCSHost matches any host.
	GetPull(ctx context.Context, repo Repository, num int) (*PullRequest, error)
	ListLocks(ctx context.Context) ([]Lock, error)
	ApplyLock(ctx context.Context) (ApplyLock, error)
	ListJobs(ctx context.Context, f JobFilter) []Job
	GetJob(ctx context.Context, id string) (Job, bool)
	// JobLog streams a job's output starting after the first `from` lines,
	// then new lines as they arrive. The channel closes when the job has
	// finished and every line was sent, when the job's output is removed, or
	// when ctx is done.
	JobLog(ctx context.Context, id string, from int) <-chan LogLine
}

// LogLine is one line of job output. N is its 1-based position in the log.
type LogLine struct {
	N    int
	Text string
}

// Actions changes state on behalf of a user.
type Actions interface {
	// DiscardLock deletes a lock and its plan. It returns false when no lock
	// exists at id.
	DiscardLock(id string, actor string) (bool, error)
	LockApplies() error
	UnlockApplies() error
}
